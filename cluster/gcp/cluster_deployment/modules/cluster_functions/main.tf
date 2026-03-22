variable "project_id" {}
variable "vpc_connector_name" {}
variable "resource_name_prefix" {}
variable "region" {}
variable "service_account_mail_id" {}
variable "asav_password_secret_name" {}
variable "asav_en_password_secret_name" {}
variable "license_token" {}
  

# Create a GCS bucket to store the Cloud Function ZIP archive
resource "google_storage_bucket" "asav_bucket" {
  name          = "${var.resource_name_prefix}-asav-autoscale-bucket"
  location      = var.region
  storage_class = "STANDARD"

  force_destroy               = true
  uniform_bucket_level_access = true
}

# Create a ZIP archive of Cluster Function Source Code
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

# Upload the ZIP archive to the created bucket
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

# Delete ZIP archive files after they've been uploaded
resource "null_resource" "cleanup_zip_files" {
  depends_on = [
    google_storage_bucket_object.asav_autoscale_scalein_action_object,
    google_storage_bucket_object.asav_autoscale_scaleout_action_object
  ]

  provisioner "local-exec" {
    command = "rm -f ${path.module}/scalein_action/scalein-action.zip ${path.module}/scaleout_action/scaleout-action.zip"
  }
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
}

resource "google_logging_project_sink" "delete_sink" {
  name                   = "${var.resource_name_prefix}-asav-delete-sink"
  destination            = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.delete.name}"
  filter                 = "resource.type = \"gce_instance\" AND protoPayload.methodName = \"v1.compute.instances.delete\" AND protoPayload.resourceName:\"${var.resource_name_prefix}\" AND operation.first=\"true\""
  unique_writer_identity = false
}

# Create Cloud Functions
resource "google_cloudfunctions_function" "scaleout_action" {
  name                          = "${var.resource_name_prefix}-asav-scaleout-action"
  runtime                       = "python312"
  entry_point                   = "scale_out"
  source_archive_bucket         = google_storage_bucket.asav_bucket.id
  source_archive_object         = google_storage_bucket_object.asav_autoscale_scaleout_action_object.name
  timeout                       = 540
  vpc_connector                 = var.vpc_connector_name
  vpc_connector_egress_settings = "PRIVATE_RANGES_ONLY"
  ingress_settings              = "ALLOW_ALL"
  min_instances                 = 0
  max_instances                 = 16

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.insert.id
  }

  environment_variables = {
    RESOURCE_NAME_PREFIX   = var.resource_name_prefix
    LICENSE_TOKEN          = var.license_token
  }

  secret_environment_variables {
    key     = "ASAV_PASSWORD"
    secret  = var.asav_password_secret_name
    version = "latest"
  }

  secret_environment_variables {
    key     = "ASAV_EN_PASSWORD"
    secret  = var.asav_en_password_secret_name
    version = "latest"
  }
}

resource "google_cloudfunctions_function" "scalein_action" {
  name                          = "${var.resource_name_prefix}-asav-scalein-action"
  runtime                       = "python312"
  entry_point                   = "scale_in"
  source_archive_bucket         = google_storage_bucket.asav_bucket.id
  source_archive_object         = google_storage_bucket_object.asav_autoscale_scalein_action_object.name
  timeout                       = 540
  vpc_connector                 = var.vpc_connector_name
  vpc_connector_egress_settings = "PRIVATE_RANGES_ONLY"
  ingress_settings              = "ALLOW_ALL"
  min_instances                 = 0
  max_instances                 = 4

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.delete.id
  }
  
  environment_variables = {
    RESOURCE_NAME_PREFIX   = var.resource_name_prefix
  }

  secret_environment_variables {
    key     = "ASAV_PASSWORD"
    secret  = var.asav_password_secret_name
    version = "latest"
  }

  secret_environment_variables {
    key     = "ASAV_EN_PASSWORD"
    secret  = var.asav_en_password_secret_name
    version = "latest"
  }
}
