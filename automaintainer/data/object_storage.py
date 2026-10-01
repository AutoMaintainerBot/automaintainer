import hashlib
import json
import os
import shutil
import logging
from typing import Dict, Optional, Tuple, Union
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("automaintainer.storage")

class StoredArtifact:
    def __init__(self, key: str, sha256: str, size_bytes: int, retention_until: datetime, data: bytes, remote_uri: Optional[str] = None):
        self.key = key
        self.sha256 = sha256
        self.size_bytes = size_bytes
        self.retention_until = retention_until
        self.data = data
        self.remote_uri = remote_uri


class S3StorageBackend:
    """
    S3 / MinIO Object Storage Driver:
    Stores and retrieves artifacts to/from AWS S3, MinIO, or compatible cloud storage,
    with AWS KMS envelope encryption and presigned URL generation.
    """
    def __init__(
        self,
        bucket_name: str,
        endpoint_url: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        region_name: str = "us-east-1",
        kms_key_id: Optional[str] = None
    ):
        self.bucket_name = bucket_name
        self.endpoint_url = endpoint_url
        self.region_name = region_name
        self.kms_key_id = kms_key_id
        self._s3_client = None

        try:
            import boto3
            self._s3_client = boto3.client(
                "s3",
                endpoint_url=self.endpoint_url,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=self.region_name
            )
        except Exception as e:
            logger.warning(f"Failed to initialize S3 client: {e}")

    def upload(self, key: str, data: bytes, metadata: Optional[dict] = None) -> Optional[str]:
        if not self._s3_client:
            return None
        try:
            extra_args = {}
            if metadata:
                extra_args["Metadata"] = {k: str(v) for k, v in metadata.items()}
            if self.kms_key_id:
                extra_args["ServerSideEncryption"] = "aws:kms"
                extra_args["SSEKMSKeyId"] = self.kms_key_id

            self._s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=data,
                **extra_args
            )
            return f"s3://{self.bucket_name}/{key}"
        except Exception as e:
            logger.error(f"S3 upload error for {key}: {e}")
            return None

    def download(self, key: str) -> Optional[bytes]:
        if not self._s3_client:
            return None
        try:
            resp = self._s3_client.get_object(Bucket=self.bucket_name, Key=key)
            return resp["Body"].read()
        except Exception as e:
            logger.error(f"S3 download error for {key}: {e}")
            return None

    def delete(self, key: str) -> bool:
        if not self._s3_client:
            return False
        try:
            self._s3_client.delete_object(Bucket=self.bucket_name, Key=key)
            return True
        except Exception as e:
            logger.error(f"S3 delete error for {key}: {e}")
            return False

    def generate_presigned_url(self, key: str, expires_in_seconds: int = 3600, http_method: str = "GET") -> Optional[str]:
        """Generates presigned URL for secure, time-limited direct object access."""
        if not self._s3_client:
            return None
        try:
            client_method = "get_object" if http_method.upper() == "GET" else "put_object"
            params = {"Bucket": self.bucket_name, "Key": key}
            return self._s3_client.generate_presigned_url(
                ClientMethod=client_method,
                Params=params,
                ExpiresIn=expires_in_seconds
            )
        except Exception as e:
            logger.error(f"S3 presigned URL generation error for {key}: {e}")
            return None

    def configure_bucket_lifecycle(
        self,
        expiration_days: int = 90,
        glacier_transition_days: int = 30,
        prefix: str = "tenants/",
    ) -> bool:
        """
        Configures hardware-level bucket lifecycle policy on AWS S3 / MinIO:
        - Transitions artifacts to GLACIER after glacier_transition_days.
        - Permanently expires and purges artifacts after expiration_days.
        """
        if not self._s3_client:
            return False
        try:
            lifecycle_config = {
                "Rules": [
                    {
                        "ID": f"automaintainer-retention-{prefix.replace('/', '_')}",
                        "Status": "Enabled",
                        "Filter": {"Prefix": prefix},
                        "Transitions": [
                            {
                                "Days": glacier_transition_days,
                                "StorageClass": "GLACIER",
                            }
                        ],
                        "Expiration": {
                            "Days": expiration_days,
                        },
                    }
                ]
            }
            self._s3_client.put_bucket_lifecycle_configuration(
                Bucket=self.bucket_name,
                LifecycleConfiguration=lifecycle_config,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to configure S3 bucket lifecycle for {self.bucket_name}: {e}")
            return False


class GCSStorageBackend:
    """
    Google Cloud Storage (GCS) Object Storage Driver:
    Stores and retrieves artifacts to/from Google Cloud Storage buckets,
    supporting Cloud KMS customer-managed encryption keys and V4 signed URLs.
    """
    def __init__(self, bucket_name: str, project_id: Optional[str] = None, kms_key_name: Optional[str] = None):
        self.bucket_name = bucket_name
        self.project_id = project_id
        self.kms_key_name = kms_key_name
        self._client = None
        self._bucket = None
        try:
            from google.cloud import storage
            self._client = storage.Client(project=self.project_id)
            self._bucket = self._client.bucket(self.bucket_name)
        except Exception as e:
            logger.warning(f"Failed to initialize GCS client: {e}")

    def upload(self, key: str, data: bytes, metadata: Optional[dict] = None) -> Optional[str]:
        if not self._bucket:
            return None
        try:
            blob = self._bucket.blob(key, kms_key_name=self.kms_key_name)
            if metadata:
                blob.metadata = {k: str(v) for k, v in metadata.items()}
            blob.upload_from_string(data)
            return f"gs://{self.bucket_name}/{key}"
        except Exception as e:
            logger.error(f"GCS upload error for {key}: {e}")
            return None

    def download(self, key: str) -> Optional[bytes]:
        if not self._bucket:
            return None
        try:
            blob = self._bucket.blob(key)
            return blob.download_as_bytes()
        except Exception as e:
            logger.error(f"GCS download error for {key}: {e}")
            return None

    def delete(self, key: str) -> bool:
        if not self._bucket:
            return False
        try:
            blob = self._bucket.blob(key)
            blob.delete()
            return True
        except Exception as e:
            logger.error(f"GCS delete error for {key}: {e}")
            return False

    def generate_presigned_url(self, key: str, expires_in_seconds: int = 3600, http_method: str = "GET") -> Optional[str]:
        if not self._bucket:
            return None
        try:
            blob = self._bucket.blob(key)
            method = "GET" if http_method.upper() == "GET" else "PUT"
            return blob.generate_signed_url(version="v4", expiration=timedelta(seconds=expires_in_seconds), method=method)
        except Exception as e:
            logger.error(f"GCS signed URL error for {key}: {e}")
            return None

    def configure_bucket_lifecycle(
        self,
        expiration_days: int = 90,
        nearline_transition_days: int = 30,
        prefix: str = "tenants/",
    ) -> bool:
        """
        Configures bucket lifecycle management on Google Cloud Storage:
        - Transitions blobs to NEARLINE after nearline_transition_days.
        - Deletes expired blobs after expiration_days.
        """
        if not self._bucket:
            return False
        try:
            rule_transition = {
                "action": {"type": "SetStorageClass", "storageClass": "NEARLINE"},
                "condition": {"age": nearline_transition_days, "matchesPrefix": [prefix]},
            }
            rule_delete = {
                "action": {"type": "Delete"},
                "condition": {"age": expiration_days, "matchesPrefix": [prefix]},
            }
            rules = list(getattr(self._bucket, "lifecycle_rules", []) or [])
            rules.extend([rule_transition, rule_delete])
            self._bucket.lifecycle_rules = rules
            if hasattr(self._bucket, "patch"):
                self._bucket.patch()
            return True
        except Exception as e:
            logger.error(f"Failed to configure GCS bucket lifecycle for {self.bucket_name}: {e}")
            return False


class ObjectStorageService:
    """
    Object Storage Backend (Multi-Tenant S3/GCS Driver with local disk caching).
    - Multi-tenant tenant namespace isolation.
    - KMS envelope encryption.
    - Presigned URL generation for time-limited artifact retrieval.
    - Cryptographic SHA-256 calculation and verification.
    - Retention TTL enforcement.
    """

    def __init__(
        self,
        storage_root: Optional[str] = None,
        s3_backend: Optional[S3StorageBackend] = None,
        gcs_backend: Optional[GCSStorageBackend] = None
    ):
        if storage_root is None:
            try:
                from automaintainer.config import get_settings
                storage_root = get_settings().STORAGE_ROOT or "./automaintainer_artifacts"
            except Exception:
                storage_root = "./automaintainer_artifacts"
        self.storage_root = storage_root
        os.makedirs(self.storage_root, exist_ok=True)
        self.s3_backend = s3_backend
        self.gcs_backend = gcs_backend
        self._index_file = os.path.join(self.storage_root, "_metadata_index.json")
        self._registry: Dict[str, StoredArtifact] = {}
        self._load_index()

    @staticmethod
    def format_tenant_key(tenant_id: Union[str, int], session_id: str, artifact_name: str) -> str:
        """Constructs multi-tenant isolated artifact storage key."""
        clean_tenant = str(tenant_id).replace("/", "_")
        clean_session = str(session_id).replace("/", "_")
        clean_name = artifact_name.lstrip("/")
        return f"tenants/{clean_tenant}/{clean_session}/{clean_name}"

    def configure_cloud_retention_policy(
        self,
        expiration_days: int = 90,
        archive_transition_days: int = 30,
        prefix: str = "tenants/"
    ) -> bool:
        """
        Configures lifecycle policies across active cloud storage backends (S3/GCS).
        """
        success = True
        if self.s3_backend:
            s3_ok = self.s3_backend.configure_bucket_lifecycle(
                expiration_days=expiration_days,
                glacier_transition_days=archive_transition_days,
                prefix=prefix
            )
            success = success and s3_ok
        if self.gcs_backend:
            gcs_ok = self.gcs_backend.configure_bucket_lifecycle(
                expiration_days=expiration_days,
                nearline_transition_days=archive_transition_days,
                prefix=prefix
            )
            success = success and gcs_ok
        return success

    def _load_index(self):
        if os.path.exists(self._index_file):
            try:
                with open(self._index_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for key, item in data.items():
                    retention = datetime.fromisoformat(item["retention_until"])
                    self._registry[key] = StoredArtifact(
                        key=key,
                        sha256=item["sha256"],
                        size_bytes=item["size_bytes"],
                        retention_until=retention,
                        data=b"",
                        remote_uri=item.get("remote_uri"),
                    )
            except Exception as e:
                logger.warning(f"Could not load storage index: {e}")

    def _save_index(self):
        try:
            data = {}
            for key, art in self._registry.items():
                data[key] = {
                    "sha256": art.sha256,
                    "size_bytes": art.size_bytes,
                    "retention_until": art.retention_until.isoformat(),
                    "remote_uri": art.remote_uri,
                }
            tmp_index = f"{self._index_file}.tmp"
            with open(tmp_index, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_index, self._index_file)
        except Exception as e:
            logger.warning(f"Could not save storage index: {e}")

    def put_object(
        self,
        key: str,
        data: bytes,
        ttl_days: int = 14,
        expected_sha256: Optional[str] = None
    ) -> StoredArtifact:
        computed_sha = hashlib.sha256(data).hexdigest()
        if expected_sha256 and expected_sha256.lower() != computed_sha.lower():
            raise ValueError(f"Integrity check failed: expected {expected_sha256}, got {computed_sha}")

        retention = datetime.now(timezone.utc) + timedelta(days=ttl_days)

        # Upload to remote cloud bucket if configured
        remote_uri = None
        if self.s3_backend:
            remote_uri = self.s3_backend.upload(
                key=key,
                data=data,
                metadata={"sha256": computed_sha, "retention_until": retention.isoformat()}
            )
        elif self.gcs_backend:
            remote_uri = self.gcs_backend.upload(
                key=key,
                data=data,
                metadata={"sha256": computed_sha, "retention_until": retention.isoformat()}
            )

        artifact = StoredArtifact(
            key=key,
            sha256=computed_sha,
            size_bytes=len(data),
            retention_until=retention,
            data=data,
            remote_uri=remote_uri
        )

        # Write to local physical storage path
        file_path = os.path.join(self.storage_root, key.replace("/", "_"))
        with open(file_path, "wb") as f:
            f.write(data)

        self._registry[key] = artifact
        self._save_index()
        return artifact

    def get_object(self, key: str) -> Optional[bytes]:
        artifact = self._registry.get(key)
        if artifact and artifact.data:
            return artifact.data

        file_path = os.path.join(self.storage_root, key.replace("/", "_"))
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                content = f.read()
                if artifact:
                    artifact.data = content
                return content

        if self.s3_backend:
            remote_data = self.s3_backend.download(key)
            if remote_data is not None:
                with open(file_path, "wb") as f:
                    f.write(remote_data)
                if artifact:
                    artifact.data = remote_data
                return remote_data
        elif self.gcs_backend:
            remote_data = self.gcs_backend.download(key)
            if remote_data is not None:
                with open(file_path, "wb") as f:
                    f.write(remote_data)
                if artifact:
                    artifact.data = remote_data
                return remote_data

        return None

    def generate_presigned_url(self, key: str, expires_in_seconds: int = 3600, http_method: str = "GET") -> str:
        """Returns signed remote cloud URL or fallback local authenticated link."""
        if self.s3_backend:
            url = self.s3_backend.generate_presigned_url(key, expires_in_seconds, http_method)
            if url:
                return url
        if self.gcs_backend:
            url = self.gcs_backend.generate_presigned_url(key, expires_in_seconds, http_method)
            if url:
                return url

        # Local storage fallback link
        file_path = os.path.join(self.storage_root, key.replace("/", "_"))
        return f"file:///{os.path.abspath(file_path).replace(os.sep, '/')}"

    def purge_expired(self) -> int:
        """Purges objects whose retention TTL has expired."""
        now = datetime.now(timezone.utc)
        expired_keys = [k for k, art in self._registry.items() if now > art.retention_until]
        for k in expired_keys:
            del self._registry[k]
            if self.s3_backend:
                self.s3_backend.delete(k)
            if self.gcs_backend:
                self.gcs_backend.delete(k)
            file_path = os.path.join(self.storage_root, k.replace("/", "_"))
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    pass
        if expired_keys:
            self._save_index()
        return len(expired_keys)

# Singleton
_storage_service: Optional[ObjectStorageService] = None
def get_object_storage() -> ObjectStorageService:
    global _storage_service
    if _storage_service is None:
        from automaintainer.config import get_settings
        settings = get_settings()
        s3_backend = None
        gcs_backend = None
        if getattr(settings, "S3_BUCKET_NAME", None):
            s3_backend = S3StorageBackend(
                bucket_name=settings.S3_BUCKET_NAME,
                endpoint_url=settings.S3_ENDPOINT_URL,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_REGION
            )
        if getattr(settings, "GCS_BUCKET_NAME", None):
            gcs_backend = GCSStorageBackend(
                bucket_name=settings.GCS_BUCKET_NAME,
                project_id=settings.GCS_PROJECT_ID,
                kms_key_name=getattr(settings, "GCS_KMS_KEY_NAME", None)
            )

        root_dir = settings.STORAGE_ROOT or "./automaintainer_artifacts"
        if not s3_backend and not gcs_backend:
            logger.warning(
                "No cloud object storage configured (S3_BUCKET_NAME and GCS_BUCKET_NAME are unset). "
                "Defaulting to local directory storage (%s). "
                "For production resilience, configure S3 or GCS bucket settings.",
                root_dir
            )

        _storage_service = ObjectStorageService(
            storage_root=root_dir,
            s3_backend=s3_backend,
            gcs_backend=gcs_backend
        )
    return _storage_service
