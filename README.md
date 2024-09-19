# Test execution environment for the web application firewalls  

## Description

This project aims to provide a standardized and reproducible testing environment for evaluating the robustness of Machine Learning (ML) based Web Application Firewalls (WAFs). It utilizes Docker to containerize the application, making it easy to run and deploy across various environments.

## Requirements

To set up and run this project, you will need to install the following software:

1. **Python**: Ensure you have Python installed. You can download it from [python.org](https://www.python.org/downloads/).

2. **Visual Studio Code**: For editing and managing the code, install Visual Studio Code from [code.visualstudio.com](https://code.visualstudio.com/) or any other editer.

3. **Docker**: Install Docker to manage and run containerized applications. You can download Docker from [docker.com](https://www.docker.com/products/docker-desktop).

## Dataset

The project utilizes the HTTP Params Dataset, which is available on Kaggle. You can download the dataset from the following link:

- [HTTP Params Dataset](https://www.kaggle.com/datasets/evg3n1j/httpparamsdataset)

## Setup and Running the Project

To run this project, follow these steps:

1. **Clone the Repository**: 
   ```bash
   git clone <repository-url>
   cd <repository-name>

2.  **To run this project, use the following command**:

    ```bash
    docker-compose up --build
   
