variable "project_id" {
  description = "The ID of the GCP project to use."
  validation {
    condition = (
      length(var.project_id) > 2 &&
      can(regex("^[0-9A-Za-z-]+$", var.project_id))
    )
    error_message = "Please provide a valid project ID."
  }
}

variable "vpc_connector_name" {
  description = "Name for the VPC connector resource for cloud functions to access VPC resources."
  validation {
    condition     = can(regex("^[A-Za-z0-9-_]+$", var.vpc_connector_name))
    error_message = "Please provide a valid VPC connector name."
  }
}

variable "resource_name_prefix" {
  description = "Prefix for naming resources in the deployment."
  validation {
    condition = (
      can(regex("^[a-zA-Z][0-9A-Za-z-_]*$", var.resource_name_prefix)) &&
      length(var.resource_name_prefix) > 1
    )
    error_message = "Prefix must start with a letter and contain only letters, numbers, dashes, or underscores."
  }
}

variable "region" {
  description = "The GCP region to create resources in."
  validation {
    condition = (
      length(var.region) > 2 &&
      can(regex("^[0-9A-Za-z-]+$", var.region))
    )
    error_message = "Please provide a valid region."
  }
}


variable "service_account_mail_id" {
  description = "Service account email used by the instances."
  validation {
    condition     = can(regex(".+@.+\\..+", var.service_account_mail_id))
    error_message = "Please provide a valid email address."
  }
}


resource "google_storage_bucket" "asav_bucket" {
  name          = "${var.resource_name_prefix}-asav-autoscale-bucket"
  location      = var.region
  storage_class = "STANDARD"

  force_destroy               = true
  uniform_bucket_level_access = true
}

data "archive_file" "asav_autoscale_scalein_action_zip" {
  type        = "zip"
  source_dir  = "${path.module}/scalein_action"
  output_path = "${path.module}/scalein_action/scalein-action.zip"
}

data "archive_file" "asav_autoscale_scaleout_action_zip" {
  type        = "zip"
  source_dir  = "${path.module}/scaleout_action"
  output_path = "${path.module}/scaleout_action/scaleout-action.zip"

}

resource "google_storage_bucket_object" "asav_autoscale_scalein_action_object" {
  name   = "scalein-action.zip"
  bucket = google_storage_bucket.asav_bucket.id
  source = data.archive_file.asav_autoscale_scalein_action_zip.output_path
}

resource "google_storage_bucket_object" "asav_autoscale_scaleout_action_object" {
  name   = "scaleout-action.zip"
  bucket = google_storage_bucket.asav_bucket.id
  source = data.archive_file.asav_autoscale_scaleout_action_zip.output_path
}

resource "google_pubsub_topic" "insert" {
  name = "${var.resource_name_prefix}-asav-pubsub-topic-insert"
}

resource "google_pubsub_topic_iam_binding" "insert" {
  topic = google_pubsub_topic.insert.id

  role = "roles/pubsub.publisher"

  members = [
    "serviceAccount:cloud-logs@system.gserviceaccount.com"
  ]
}

resource "google_pubsub_topic" "delete" {
  name = "${var.resource_name_prefix}-asav-pubsub-topic-delete"
}

resource "google_pubsub_topic_iam_binding" "delete" {
  topic = google_pubsub_topic.delete.id

  role = "roles/pubsub.publisher"

  members = [
    "serviceAccount:cloud-logs@system.gserviceaccount.com"
  ]
}

# Create Logging Sinks
resource "google_logging_project_sink" "insert_sink" {
  name                   = "${var.resource_name_prefix}-asav-insert-sink"
  destination            = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.insert.name}"
  filter                 = "resource.type = \"gce_instance\" AND protoPayload.methodName = \"v1.compute.instances.insert\" AND operation.last = \"true\" AND protoPayload.resourceName:\"${var.resource_name_prefix}\""
  unique_writer_identity = false
  depends_on             = [google_pubsub_topic.insert]
}

resource "google_logging_project_sink" "delete_sink" {
  name                   = "${var.resource_name_prefix}-asav-delete-sink"
  destination            = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.delete.name}"
  filter                 = "resource.type = \"gce_instance\" AND protoPayload.methodName = \"v1.compute.instances.delete\" AND protoPayload.resourceName:\"${var.resource_name_prefix}\" AND operation.first=\"true\""
  unique_writer_identity = false
  depends_on             = [google_pubsub_topic.delete]
}

# Create Cloud Functions
resource "google_cloudfunctions_function" "scaleout_action" {
  name                          = "${var.resource_name_prefix}-asav-scaleout-action"
  runtime                       = "python312"
  entry_point                   = "change_pass"
  source_archive_bucket         = google_storage_bucket.asav_bucket.id
  source_archive_object         = google_storage_bucket_object.asav_autoscale_scaleout_action_object.name
  timeout                       = 540
  min_instances                 = 0
  max_instances                 = 1
  vpc_connector                 = var.vpc_connector_name
  vpc_connector_egress_settings = "PRIVATE_RANGES_ONLY"
  ingress_settings              = "ALLOW_ALL"

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.insert.id
  }

  environment_variables = {
    RESOURCE_NAME_PREFIX = var.resource_name_prefix
  }
}

resource "google_cloudfunctions_function" "scalein_action" {
  name                          = "${var.resource_name_prefix}-asav-scalein-action"
  runtime                       = "python312"
  entry_point                   = "lic_dereg"
  source_archive_bucket         = google_storage_bucket.asav_bucket.id
  source_archive_object         = google_storage_bucket_object.asav_autoscale_scalein_action_object.name
  timeout                       = 300
  min_instances                 = 0
  max_instances                 = 1
  vpc_connector                 = var.vpc_connector_name
  vpc_connector_egress_settings = "PRIVATE_RANGES_ONLY"
  ingress_settings              = "ALLOW_ALL"

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.delete.id
  }

  environment_variables = {
    RESOURCE_NAME_PREFIX = var.resource_name_prefix
  }
}

# Outputs
output "scale_out_function_name" {
  value = google_cloudfunctions_function.scaleout_action.name
}

output "scale_in_function_name" {
  value = google_cloudfunctions_function.scalein_action.name
}
