# Tracer

# Running on the cloud
## GCP
- Create the virtual machine
- Upload the binary: `gcloud compute scp target/release/tracer instance-20240625-113002:~  --zone us-central1-f`
- Acess the machine: `gcloud compute ssh --zone "us-central1-f" "instance-20240625-113002" --project "internetmeasurmentneigboors"`
- Run: `./tracer`
