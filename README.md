# Auth Service

This document provides instructions for building and running the Auth Service application locally or using Docker.

--------------------------------

## FULLY LOCAL: Building and Running the Application Locally

To run the application locally, we use `app.db` as a simple SQLite database for testing purposes. Ensure the following configuration is correct:

- The `SQLALCHEMY_DATABASE_URL` property in `app/core/config.py` should point to `"sqlite:///./app.db"` instead of PostgreSQL.

### Steps to Start the Backend Locally (Without Docker)

1. Open a terminal and navigate to the `auth-service` directory:

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   > **Tip:** If you're using VSCode, you can use the command palette (`Ctrl+Shift+P`) and select **Python: Create Environment** to create a virtual environment and install dependencies.

3. Generate and apply database migrations:
   ```bash
   alembic revision --autogenerate -m "Initial migration"
   alembic upgrade head
   ```

4. (Optional) Initialize some sample data:
   ```bash
   python -m app.initDB
   ```

5. Start the application locally:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

The backend will now be running at `http://localhost:8000`.

---

## DOCKER: Building and Running the Application with Docker

When you're ready to use Docker, follow these steps:

1. Build and start the application:
   ```bash
   docker compose up --build
   ```

   This will create two containers based on the `docker-compose.yml` file:
   - **auth-db**: A PostgreSQL database for the Auth Service.
   - **auth-service**: A FastAPI application for the Auth Service.

### Data Initialization for Sample Data

If the containers are already running, you can initialize sample data using the following command:
```bash
docker compose exec auth-service python -m app.initDB
```

---

### Cleaning Up

Use the following commands to clean up your environment:

- **Delete existing containers, volumes, and networks**:
  ```bash
  docker compose down -v
  ```

- **Stop services but keep the database and data**:
  ```bash
  docker compose down
  ```

- **Reset the environment completely and rebuild images and containers**:
  ```bash
  docker compose down -v && docker compose up --build
  ```

---

## KUBERNETES: Deploying and Running the Application with Kubernetes

To deploy the Auth Service using Kubernetes, follow these steps:

## Prerequisites

- Ensure you have `kubectl` installed and configured to interact with your Kubernetes cluster.
- A running Kubernetes cluster (local or cloud-based). 
- For local cluster, use **Minikube**, refer to [Minikube Installation](https://minikube.sigs.k8s.io/docs/start/?arch=%2Flinux%2Fx86-64%2Fstable%2Fbinary+download) 

```bash
minikube start
```

### Set up Kubernetes namespace and necessary environment variables
1. **Create a Kubernetes namespace**: Using the same namespace for all 3 microservices (auth, inventory and order)
  ```bash
  kubectl create namespace stox
  ```

2. **Set the namespace as the default for your current context**:
  ```bash
  kubectl config set-context --current --namespace=stox
  ```
3. **Install Sealed Secrets Controller**:
    If you haven't already installed the Sealed Secrets controller, follow the instructions in the [Sealed Secrets GitHub repository](https://github.com/bitnami-labs/sealed-secrets).

5. **Create a Kubernetes Secret for Database Credentials**:
    Generate a standard Kubernetes secret file:
    ```bash
    kubectl create secret generic auth-secrets --namespace stox \
      --from-literal=POSTGRES_USER=$POSTGRES_USER \
      --from-literal=POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
      --from-literal=POSTGRES_DB=$POSTGRES_DB \
      --dry-run=client -o yaml > ./k8s/raw-auth-secret.yaml
    ```

6. **Encrypt the Secret Using Sealed Secrets**:
    Use the `kubeseal` command to encrypt the secret:
    ```bash
    kubeseal --format=yaml < ./k8s/raw-auth-secret.yaml > ./k8s/sealed-auth-secret.yaml
    ```

    Ensure the `kubeseal` command is configured to use the public key of your Sealed Secrets controller.

7. **Apply the Sealed Secret**:
    Deploy the sealed secret to your Kubernetes cluster:
    ```bash
    kubectl apply -f ./k8s/sealed-auth-secret.yaml
    ```

8. **Verify the Sealed Secret is Created**:
    Check that the sealed secret is successfully created:
    ```bash
    kubectl get sealedsecrets
    ```

### Steps to build Docker images to be later deployed by Kubernetes (Minikube)
1. **Use Docker inside Minikube**:
    ```bash
    eval $(minikube docker-env)
    ```

2. **Build Docker images directly in Minikube**: Once set, any Docker images built using the docker command will be built within the Minikube VM.
    ```bash
    # Build the auth-service Docker image:
    docker build -t auth-service:latest -f Dockerfile.api .
    # Build the auth-db (PostgreSQL) Docker image:
    docker build -t auth-db:latest -f Dockerfile.db .
    # Verify the images are available in Minikube:
    docker images
    ```
---

### Steps to configure directories for a persistent volume holding persistent data of database services
1. **Create directories for persistent volumes in Minikube**
    ```bash
    # Access the Minikube VM
    minikube ssh
    # Create the directories for persistent volumes of database services
    sudo mkdir -p /var/lib/storage/auth-db
    ```
2. **Allow the postgres user to manage the persistent volume - the directory on host machine**
    ```bash
    # Ensure correct ownership and permission for the persistent volume (hostPath)
    sudo chown -R 999:999 /var/lib/storage/auth-db
    sudo chmod -R 700 /var/lib/storage/auth-db
    ```
3. **Specify the user in configuration file of k8s**
    ```yaml
    # e.g. auth-db-deployment.yaml
    spec:
      securityContext:
        fsGroup: 999
      containers:
      - name: auth-db
        image: auth-db:latest
        imagePullPolicy: IfNotPresent
        securityContext:
          runAsUser: 999
          runAsGroup: 999
    ```
4. **Verify the user who is running a pod**
This configuration is well-suited for a database application where security and controlled access to files and processes are critical.
```bash
# Example Results
kubectl exec -it auth-db-0 -- id
# uid=999 gid=999(ping) groups=999(ping)
kubectl exec -it auth-service-86f7f8fc65-mfgt2 -- id
# uid=10001(appuser) gid=10001(appuser) groups=10001(appuser),100(users)
```

---

### Steps to Deploy

1. **Apply Kubernetes Manifests**:
    Use the provided YAML files in the `k8s` directory to deploy the application:
    ```bash
    kubectl apply -f k8s/
    ```
    This will deploy the following resources:
    - A PostgreSQL database as a `StatefulSet`.
    - The Auth Service application as a `Deployment`.
    - Services to expose the database and application.

2. **Verify the Deployment**:
    Check the status of the pods:
    ```bash
    kubectl get pods
    ```
    Check the status of the services:
    ```bash
    kubectl get services
    ```
3. **Access the Application**:
    If a `NodePort` service is configured, you can access the application using the IP address of any node in the cluster and the assigned NodePort. For example:

    ```
    http://<node-ip>:<node-port>
    ```

    Replace `<node-ip>` with the IP address of a cluster node and `<node-port>` with the port number assigned to the service.

    There are 2 ways to find the exposed URL.
    - Get the url directly returned by Minikube
    ```bash
    minikube service auth-service --url
    ```
    ```bash
    # URL:
    http://192.168.49.2:31944
    ```
    - Examine the service and nodes
    ```bash
    # Get the NodePort
    kubectl get service auth-service
    ```
    ```txt
    # Example Output: get the 2nd port in the PORT(S) columne
        NAME               TYPE       CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
    auth-service  NodePort   10.104.79.185   <none>        8001:31944/TCP   10m
    ```
    ```bash
    # Get the Node IP
    kubectl get nodes -o wide
    ```
    ```bash
    # Example Output: the Internal-IP shows the node IP
        NAME           STATUS   ROLES           AGE   VERSION   INTERNAL-IP     EXTERNAL-IP
    minikube       Ready    control-plane   10m   v1.26.0   192.168.49.2    <none>
    ```


---

### Data Initialization for Sample Data

To initialize sample data, execute the following command:

```
kubectl exec -it <auth-service-pod> -- python -m app.initDB
```

Replace `<auth-service-pod>` with the name of the running pod.

---

### Cleaning Up

To stop Kubernetes services, you can delete or scale down the resources associated with the service. Here are the common ways to stop Kubernetes services:

---

#### **1. Delete the Service**
To completely stop and remove a service, use the `kubectl delete` command:

```bash
kubectl delete service <service-name> -n <namespace>
```

Example:
```bash
kubectl delete service auth-service -n default
```

This will stop the service and remove it from the cluster.

---

#### **2. Scale Down the Deployment**
If you want to stop the service but keep its configuration, you can scale down the associated deployment or StatefulSet to `0` replicas:

```bash
kubectl scale deployment <deployment-name> --replicas=0 -n <namespace>
```

Example:
```bash
kubectl scale deployment auth-service --replicas=0 -n default
```

This will stop all pods associated with the service, effectively stopping the service without deleting it.

---

#### **3. Delete the Entire Application**
If the service is part of a larger application (e.g., defined in a YAML manifest), you can delete all associated resources:

```bash
kubectl delete -f <manifest-file-or-directory>
```

Example:
```bash
kubectl delete -f k8s/
```

This will delete the service, deployments, StatefulSets, and other resources defined in the manifest.

---

#### **4. Stop Minikube (If Using Minikube)**
If you're running Kubernetes locally with Minikube, you can stop the entire Minikube cluster:

```bash
minikube stop
```

This will stop all services and resources running in the Minikube environment.

---

#### **5. Verify the Service is Stopped**
After stopping the service, you can verify it is no longer running:

```bash
kubectl get services -n <namespace>
```

If the service is stopped, it will no longer appear in the output.
