# Testing Setup

To be able to run all test cases successfully, you need access to any S3 instance.

The easiest solution is to just start a minio test instance in a local container:

```
mkdir -p minio_data
```

```
docker run \
   -d \
   -p 9000:9000 \
   -p 9090:9090 \
   --name minio \
   --restart always \
   -v ./minio_data:/data \
   -e "MINIO_SERVER_URL=http://localhost:9000" \
   -e "MINIO_ROOT_USER=root" \
   -e "MINIO_ROOT_PASSWORD=123SuperSafe" \
   quay.io/minio/minio server /data --console-address ":9090"
```

## Env Vars

The test cases will read some env vars for the s3 config:

```
S3_URL=http://localhost:9000
S3_BUCKET=<AnyBucketYouHaveAccessTo>
S3_REGION=<S3Region>
S3_KEY=<AccessKeyFromYourInstance>
S3_SECRET=<AccessSecretFromYourInstance>
```
