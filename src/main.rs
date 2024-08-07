#![allow(dead_code)] // NOTE: 2024-08-06: Ignoring dead code for now.
extern crate queryst;
extern crate serde_cbor;

use bytes::Bytes;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::ParseIntError;
use std::str::FromStr;

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper::server::conn::http1;
use tokio::net::TcpListener;
use log::{debug, info, trace, warn};
use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg};
use std::env;
use std::fs::File;
use std::io::{self, Read};
use serde::{Deserialize, Serialize};
use sqlx::{migrate::MigrateDatabase, sqlite::SqliteQueryResult, Sqlite, SqlitePool, Row };

const INDEX: &str = r#"
<!doctype html>
<html>
    <head>
        <title>EzekTec Inc. Microservices</title>
    </head>
    <body>
        <h3>EzekTec Inc Microservice...implemented by Engr. Stephen E. ( <span><p> stephen.ezekwem@gmail.com </p></span> )</h3>
    </body>
</html>
"#;

const ERROR_INDEX: &str = r#"
<!doctype html>
<html>
    <head>
        <title>EzekTec Inc. Microservices - 404 - </title>
    </head>
    <body>
        <h2> 404 - NOT FOUND </h2>
    </body>
</html>
"#;

const HEALTH_CHECK: &str = r#"
<!doctype html>
<html>
    <head>
        <title>EzekTec Inc Microservices - Health Check - </title>
    </head>
    <body>
        <p> If you have reached this link, this machine is still alive! </p>
    </body>
</html>
"#;

async fn create_schema(db_url: &str) -> Result<SqliteQueryResult, sqlx::Error> {
    let pool = SqlitePool::connect(db_url).await?;
    let qry = 
            "PRAGMA foreign_keys = ON ;
            CREATE TABLE IF NOT EXISTS settings
                (
                    settings_id             INTEGER PRIMARY KEY NOT NULL,
                    description             TEXT                NOT NULL,
                    created_on              DATETIME DEFAULT (datetime('now','localtime')),
                    updated_on              DATETIME DEFAULT (datetime('now','localtime')),
                    done                    BOOLEAN             NOT NULL DEFAULT 0
                );    
            CREATE TABLE IF NOT EXISTS project
                (
                    project_id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_name                 TEXT ,
                    created_on                   DATETIME DEFAULT (datetime('now','localtime')),
                    updated_on                   DATETIME DEFAULT (datetime('now','localtime')),
                    img_directory                TEXT NOT NULL,
                    out_directory                TEXT NOT NULL,
                    status                       TEXT NOT NULL,
                    settings_id                  INTEGER  NOT NULL DEFAULT 1,
                    FOREIGN KEY (settings_id)    REFERENCES settings (settings_id) ON UPDATE SET NULL ON DELETE SET NULL
                );";

    let result = sqlx::query(qry).execute(&pool).await;
    pool.close().await;

    result

}
// API microservice health check. (e.g. 0.0.0.0:3000/health)
async fn health_check
(
    _: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from(
        "Welcome to rust hyper implemented Microservice!",
    ))))
}

// API microservice payload json rust struct. This mirrors the exact datastructure for the project
// table and the json payload from the client system.
#[derive(Debug, Serialize, Deserialize, Default)]
struct Project {
    product_id: u32,
    product_name: String,
    created_on: String,
    updated_on: String,
    img_directory: String,
    out_directory: String,
    status: String,
    settings_id: u32
}

// API microservice delete payload json rust struct.
#[derive(Debug, Serialize, Deserialize, Default)]
struct DeleteProduct {
    product_id: u32,
}
impl DeleteProduct {
    fn get_product_id(&self) -> u32 {
        self.product_id
    }
}
impl FromStr for DeleteProduct {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<u32>() {
            Ok(id) => Ok( DeleteProduct{ product_id: id } ),
            Err(err) => Err(err),
        }

    }
}
// API microservice -- get a single project from the database.
async fn get_a_product
(
    id: u32,
    db_conn: sqlx::SqlitePool
) -> Result<String, sqlx::error::Error> {
    let qry ="
        SELECT * FROM project WHERE project_id = ? 
    "; 
    let response = sqlx::query(qry)
        .bind(id)
        .fetch_all(&db_conn)
        .await?;

    let result = response
        .into_iter()
        .map(|row| Project {
            product_id: row.get(0),
            product_name: row.get(1),
            created_on: row.get(2),
            updated_on: row.get(3),
            img_directory: row.get(4),
            out_directory: row.get(5),
            status: row.get(6),
            settings_id: row.get(7)
        })
        .collect::<Vec<Project>>();

    Ok(serde_json::to_string(&result).unwrap())
}

// API microservice -- get all the projects from the database.
async fn get_products
(
    db_conn: sqlx::SqlitePool
) -> Result<Vec<Project>, sqlx::error::Error> { 
    let qry ="
        SELECT * FROM project; 
    "; 
    let response = sqlx::query(qry)
        .fetch_all(&db_conn)
        .await?;

    let result = response
        .into_iter()
        .map(|row| Project {
            product_id: row.get(0),
            product_name: row.get(1),
            created_on: row.get(2),
            updated_on: row.get(3),
            img_directory: row.get(4),
            out_directory: row.get(5),
            status: row.get(6),
            settings_id: row.get(7)
        })
        .collect::<Vec<Project>>();

    Ok(result)
}

// API microservice -- remove a project record from the database.
async fn delete_product
(
    id: u32,
    db_conn: sqlx::SqlitePool,
) -> Result<String, sqlx::error::Error> {
    let qry ="
        DELETE FROM project WHERE project_id = ? 
    "; 
    let result = sqlx::query(qry)
        .bind(id)
        .execute(&db_conn)
        .await;

    Ok(format!("Record successfully deleted from database table!: {:?}", result))
}

// API microservice -- service request enum dictating the microservice operation to perform.
// TODO: 2024-08-06: Refactor this enum to remove the repettion of 'product_id' on all enum
// variant.
#[derive(Debug, Deserialize)]
#[serde(tag = "distribution", content = "parameters", rename_all="lowercase")]
enum ServiceRequest {
    ListProducts,
    GetProduct {
        product_id: u32,
    },
    DeleteProduct {
        product_id: u32,
    },
    CreateProduct {
        product: Project,
    },
}

// API microservice -- add a project record to the database.
async fn create_product
(
    req: Project,
    db_instance: sqlx::SqlitePool
) -> Result<String, sqlx::error::Error> {
    let qry ="
        INSERT INTO project (project_id, product_name, created_on, updated_on, img_directory, out_directory, status, settings_id) 
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
    "; 
    let result = sqlx::query(qry)
        .bind(req.product_id)
        .bind(req.product_name)
        .bind(req.created_on)
        .bind(req.updated_on)
        .bind(req.img_directory)
        .bind(req.out_directory)
        .bind(req.status)
        .bind(req.settings_id)
        .execute(&db_instance).await;

    Ok(format!("Record successfully added to database table!: {:?}", result))
}
// API microservice -- service response struct for ease of passing content back to the client..
#[derive(Deserialize, Serialize)]
struct ServiceResponse {
    status: u8,
    result: String,
}
impl ServiceResponse {
    fn init(status: u8, result: String) -> Self {
        Self {
            status,
            result
        }
    }
}

// NOTE: (2024-08-06) - return the API microservice data response as varying JSON RPC formats.
// TODO: 2024-08-06: Refactor this function into a 'helper' library.
fn serialize
(
    format: &str, 
    resp: &ServiceResponse
) -> Result<Vec<u8>, Box< dyn std::error::Error >> {
    match format {
        "json" => { 

            Ok( serde_json::to_vec(&resp)? ) 
        },
        // implement additional data serialization formats that meets your specific use-cases.
        //"cbor" => Ok( serde_cbor::to_vec(&resp)? ),
        _ => {
            Err( 
                Box::new( 
                    std::io::Error::new( std::io::ErrorKind::InvalidInput, "Invalid format" ) 
                ) 
            )
        },
    }
}

// NOTE: (2024-08-06) - return the API microservice data as a HTTP response.
// TODO: 2024-08-06: Refactor this function into a 'helper' library.
fn package_response
( 
    resp: Option<Vec<u8>>, 
    status_code: StatusCode
) -> Result< Response<BoxBody<Bytes, Infallible>>, hyper::Error > {
    let body = match resp {
        Some(body) => body,
        None => "".into() // Bytes::from( "" ),
    };
    Ok(
        Response::builder()
            .status(status_code)
            .body(full(body))
            .unwrap()
    )
}
// NOTE: (2024-08-06) - [PROPOSED] the replacement main API microservice handler that routes/serves the client service request
// to the right microservices function
// TODO: 2024-08-06: Refactor this function into a 'helper' library.
async fn _response_with_code
(
    request: ServiceRequest, 
    pool_instance: SqlitePool
) -> Result< Response<BoxBody<Bytes, Infallible>>, hyper::Error > {
    match request {
        ServiceRequest::ListProducts => {
            let projects = get_products(pool_instance.clone())
                .await
                .map_err(|_| "Error fetching products");

            let mut result = String::new();

            for project in projects.iter() {
                let projects_in_json = serde_json::to_string(project)
                    .unwrap_or("Error: database response convertion issue".to_string());

                result.push_str(&projects_in_json);
            }

            // package the service response into a struct for ease of passing content around.
            let service_resp = ServiceResponse::init(200, result); 
            let service_resp_serialized = serialize("json", &service_resp).unwrap();

            //NOTE: (2024-08-01) - handle the logic for the right 'StatusCode' to emitt.
            let mut status_code = StatusCode::OK; 
            if service_resp_serialized.is_empty() {
                status_code = StatusCode::INTERNAL_SERVER_ERROR;
            } 

            let packaged_response = package_response(
                Some(serde_json::to_vec(&service_resp_serialized).unwrap()), // packing the
                // 'ServiceResponse' into a json structure fit for emitting to the client.
                // FIXME: (2024-08-01) - this is not code logic correct. Why are we passing in a status-code? Can't
                //the system figure out if the service ran ok or not, then emitt the right status
                //code to the client.
                status_code,
            );
            packaged_response
        },
        ServiceRequest::GetProduct { product_id } => {
            let projects = get_a_product(product_id, pool_instance.clone())
                .await
                .map_err(|_| "Error fetching products");
            let service_resp = ServiceResponse::init
                (
                    200, 
                    projects.unwrap_or("No projects found".to_string()
                )
            );
            let service_resp_serialized = serialize("json", &service_resp).unwrap();
            let packaged_response = package_response(
                Some(serde_json::to_vec(&service_resp_serialized).unwrap()), 
                StatusCode::OK
            );
            Ok( packaged_response? )

        },
        _ => {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("Not found".to_string()))
                .unwrap())
        },
    }
}

// NOTE: (2024-08-06) - [CURRENT] the current main API microservice handler that routes/serves the client service request
// to the right microservices function. 
// TODO: 2024-08-06: Replace this with_ '_response_with_code' here in this file.
async fn service_handlers
(
    req: Request<hyper::body::Incoming>,
    db_instance: sqlx::SqlitePool
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/home") => { 
             Ok(Response::new(full(INDEX)))
        },
        (&Method::GET, "/health") => Ok(Response::new(full(HEALTH_CHECK))),
        (&Method::GET, path) if path.starts_with("/products/") => {
            // NOTE: this is an alternate approach to using the 'queryst' crate to read request
            // parameters and unpack the result into the format/struct of your choosing.
             //let format = {
             //   let uri = req.uri().query().unwrap_or("");
             //   let query = queryst::parse(uri).unwrap_or(serde_json::Value::Null);
             //   query["format"].as_str().unwrap_or("json").to_string()
             //};
            // NOTE: using the 'hyper::request::Request' to extract the 'id' path/parameter from
            // the request URI. This relies only on the hyper crate to work with URI's.
            let id = req
                .uri()
                .path()
                .split('/')
                .nth(2)
                .and_then(|id| id.parse::<u32>().ok());

            match id {
                Some(id) => {
                    let result = get_a_product(id, db_instance).await.unwrap();
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(full(result))
                        .unwrap(); // if this unwrap fails, the system should just panic as we con't

                    Ok(response)
                },
                None => {
                    let response = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::new("Error: Invalid id".into()).boxed())
                        .unwrap(); // if this unwrap fails, the system should just panic as we con't
                    Ok(response)
                }
            }
        },
        (&Method::GET, "/products") => {
            // NOTE: (commented out code) - just another example of the implementation of this API service using the '_response_with_code' handler. The main benefit here is the reduced size of the code, which doesn't mean the code here cannot be refactored to make it smaller.
            /*
            let result = _response_with_code(ServiceRequest::ListProducts, db_instance)
                .await.unwrap_or_else(|_| Response::new( full( "Error fetching products" ) ) );
            Ok( result  )
            */
            let projects = get_products(db_instance).await.map_err(|_| "Error fetching products");
            let mut result = String::new();

            for project in projects.iter() {
                let projects_in_json = serde_json::to_string(project)
                    .unwrap_or("Error: database response convertion issue".to_string());

                result.push_str(&projects_in_json);

            }

            let response = Response::builder()
                .status(StatusCode::OK)
                .body(full(result))
                .unwrap();

            Ok(response) 
        },
        (&Method::POST, "/products") => {
            let whole_body =  req.collect().await?.to_bytes();
            let project = serde_json::from_slice::<Project>(&whole_body)
                .map_err(|err| format!("Error: Invalid request body issue: {:?}", err));

            let result = create_product(
                    project.unwrap_or(Project::default()), 
                    db_instance 
                )
                .await
                .unwrap_or_else(|error| format!("Error: database create product issue: {:?}",error));

            let response = Response::builder()
                .status(StatusCode::OK)
                .body(full(result))
                .unwrap();

            Ok(response)
        },
        (&Method::DELETE, path) if path.starts_with("/products/")=> {
            //let whole_body =  req.collect().await?.to_bytes();
            let product_id = req
                .uri()
                .path()
                .split('/')
                .nth(2)
                .and_then(|id| id.parse::<DeleteProduct>().ok());

            match product_id {
                Some(id) => {
                    let result = delete_product(id.get_product_id(), db_instance).await.unwrap();
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(full(result))
                        .unwrap(); // if this unwrap fails, the system should just panic as we con't

                    Ok(response)
            },
                None => {
                    let response = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(full("Not found".to_string()))
                        .unwrap();

                    Ok(response)
                }
            }
        },
        _ => { 
                let response = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(ERROR_INDEX.into()).boxed())
                    .unwrap(); // if this unwrap fails, the system should just panic as we con't

                Ok(response)
        },
    }
}

// NOTE: (2024-08-06) -- [HELPERs] -- these are helper functions that are used in the main API
// microservice handler.
// TODO: 2024-08-06: Refactor these into a 'helper' library.
// [[--
fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> {
    Full::new(chunk.into()).boxed()
}
fn _empty() -> BoxBody<Bytes, Infallible> {
    Empty::<Bytes>::new().boxed()
}
// --]]

#[derive(Debug)]
pub struct Db {
    pool: SqlitePool,
    file_path: String
}
impl Db {
    pub async fn init_db() -> Self {
        let file_path = String::from("sqlite://users.db");
        let pool = SqlitePool::connect(&file_path).await.unwrap();

        Self {
            pool,
            file_path
        }
    }
    pub fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }
    pub fn get_file_path(&self) -> &str {
        &self.file_path
    }
}

#[derive(Deserialize)]
struct Config {
    address: String,
}

// NOTE: (2024-08-06) -- [MAIN] -- this is the main API microservice handler.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
     pretty_env_logger::init();

    // NOTE: (2024-08-06) - Read mciroservice configurations from the config file -- microserves.toml -- in the current working
    // directory of this server.
    let config = File::open("microserves.toml")
            .and_then(|mut file| {
                let mut buffer = String::new();
                file.read_to_string(&mut buffer)?;

                Ok(buffer)
            })
            .and_then(|buffer| {
                toml::from_str::<Config>(&buffer)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            })
            .map_err(|err| {
                warn!("Can't read config file: {}", err);
            })
            .ok();

    // Read in server address and config file from command line!
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::with_name("address")
            .short("a")
            .long("address")
            .value_name("ADDRESS")
            .help("Sets server address")
            .default_value("0.0.0.0:3000")
            .takes_value(true)) 
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("Sets a custom config file")
            .takes_value(true)) 
        .get_matches();

    let address = matches.value_of("address")
        .map(|s| {
            info!("Server address from command line: {}", s);
            s.to_owned()
        })
        .or(env::var("ADDRESS").ok())
        .and_then(|addr| {
            let addr = addr.parse().ok();
            info!("Server address from .env file: {:?}", addr);
            addr
        })
        .or(
            config.map(|config| {
                info!("Server address from microservices.toml file: {}", config.address);
                config.address
            })
        )
        .or_else(|| {
            let socket_addr: SocketAddr = ([0, 0, 0, 0], 3000).into();
            Some(socket_addr.to_string())
        })
        .unwrap();

    info!("EzekTec-Inc Microservices - v0.1.0");
    // Open an instance to the database pool in order to send sql commands to it.
    // let db_url = String::from("sqlite://users.db");
    // let instances = SqlitePool::connect(&db_url).await.unwrap();
    trace!("Starting database...");
    let db: Db = Db::init_db().await;
    let database_url: &str = db.get_file_path(); //<--this is the path to the sqlite file

    if !Sqlite::database_exists(&database_url).await.unwrap_or(false) {
        let _ = Sqlite::create_database(&database_url).await.map_err(
            |err| format!("Error: database create issue: {:?}", err)
        );
        trace!("Creating database schema...");
        match create_schema(&database_url).await {
            Ok(_) => {
                // Check to see if the `settings` table exists. 
                let qry = "SELECT COUNT(*) FROM settings";
                let result = sqlx::query(&qry).execute(db.get_pool()).await;
                let result = format!("{:?}", result.map_err(
                                            |err| 
                                            format!(
                                                "Error: database create schema issues: {:?}", 
                                                err.to_string()
                                            )
                                         )
                );
                if result.contains('0')  {
                    // If it does, add a record to prime the db table
                    let qry ="INSERT INTO settings (description) VALUES()";
                    let result = sqlx::query(&qry)
                        .bind("testing")
                        .execute(db.get_pool())
                    .await;
                    tracing::info!("`settings` table instantiated: {:?} ", &result);
                    println!("{:?}", result);
                }

                println!("Database created Sucessfully");
            },
            Err(e) => panic!("{}",e),
        }
    }

    let addr = SocketAddr::from(address.parse::<SocketAddr>().unwrap());
    debug!("Trying to bind server to address: {}", &addr);

    let pool = db.get_pool().clone();
    debug!("Database started with pool conn: {}", &pool.size());

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{} ", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let pool = pool.clone();
        tokio::task::spawn(async move {
            let service = service_fn(
                move |req| {
                    let pool = pool.clone();
                    trace!("Incoming request: {:?}", req);
                    service_handlers(req, pool)
                }
            );

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

