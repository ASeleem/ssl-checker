 
# SSL Checker

This repository contains ssl checker app

## Setup and run

1. Clone this repository:
   ```sh
   git clone https://github.com/aseleem/ssl-checker-sap-task-01.git
   cd ssl-checker-sap-task-01

2. Build the docker image and push it to the AWS ECR
   ```sh
   docker build -t ssl-checker .
   

3. run ssl checker
    ```sh
    docker run --rm -it ssl-checker google.com
    docker run --rm -it ssl-checker revoked-rsa-dv.ssl.com
    docker run --rm -it ssl-checker expired-rsa-dv.ssl.com
