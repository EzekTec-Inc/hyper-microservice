# Hyper-Microservices

This project is a microservices implementation in Rust using various powerful crates to handle web services, database interactions, asynchronous programming, and more. The primary goal is to create a scalable, maintainable, and efficient microservices architecture.

## Table of Contents

- [Getting Started](#getting-started)
- [Features](#features)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Rust (latest stable version)
- Docker (for running databases)

### Features

- **Hyper**: A fast and correct HTTP implementation.
- **Sqlx**: Asynchronous SQL queries with compile-time checking.
- **TailwindCSS**: A utility-first CSS framework for rapid UI development.
- **Tokio**: An asynchronous runtime for the Rust programming language.
- **Futures**: Abstractions for asynchronous programming.
- **Serde and Serde_json**: Serialization and deserialization.
- **Dotenv**: Loading environment variables from a `.env` file.
- **Failure**: Error handling library.
- **Queryst**: Convenient SQL query creation.
- **Clap**: Command-line argument parsing.
- **Pretty_env_logger**: A logger with nice formatting.
- **Bytes**: Utilities for working with bytes.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/ezektec-inc/hyper-microservices.git
    cd hyper-microservices
    ```

2. Install Rust and Cargo (if not already installed):
    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

3. Install the required dependencies:
    ```sh
    cargo build
    ```

4. Set up your environment variables by copying `.your_env` to `.env` and filling in the required values:
    ```sh
    cp .<your_env> .env
    ```

5. Run the application:
    ```sh
    cargo RUST_LOG=hyper_microservce=trace,warn,debug cargo watch -x run
    ```

## Usage

Once the application is running, you can access the different microservices via their respective endpoints. For example, you can interact with the API using tools like `curl` or Postman.

### Example API Request

```sh
curl -X GET http://0.0.0.0:3000/health
```

```sh
curl -X GET http://0.0.0.0:3000/products
```

```sh
curl -X GET http://0.0.0.0:3000/products/1
```

```sh
curl -X GET http://0.0.0.0:3000/products -H "Content-Type: application/json" 
-d 
'{
    "product_id": 3, 
    "product_name": "Your Product Name", 
    "created_on": "2024-08-01", 
    "updated_on": "2024-08-06", 
    "img_directory": "path/to/img", 
    "out_directory": "path/to/project", 
    "status": "In-Progress", 
    "settings_id": "1" 
}'
```

### NOTE:
The following files have been included in this repository to help you get started and to test the microservices. It is expected that you'll delete these files or modify them to suite your usage.

```sh 
.env
users.db
microservices.toml
```
