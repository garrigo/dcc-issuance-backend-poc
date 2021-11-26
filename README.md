# SPS Project 2021

Simple micro service for querying flights data.

---

## How to test (POSTGRES)

### Using docker
- Create a file `.env` with a parameter "DATABASE_URL" with the connection string to the database
  - DATABASE_URL=postgresql://postgres:password@%your-ip%:5432/sps
- Build the image with `docker build -t sps -f Dockerfile_pg .`
- Run a container with postgres `docker run -p 5432:5432 --rm --name "sps_db" -e "POSTGRES_USER=postgres" -e "POSTGRES_PASSWORD=password" -e "POSTGRES_DB=sps" -d postgres`
- Wait a few second for the container to spin up completely, then create the data structure: `sh ./initializeDB_pg`
- Spin app the application container: `docker run -p 5000:5000 --rm --name "sps" -d sps`
- When needed, stop the containers with `docker stop sps sps_db`
- Open 'localhost:5000' on a browser

### Using OS
- Clone the repository and `cd` into it
- Create a file `.env` with a parameter "DATABASE_URL" with the connection string to the database
  - DATABASE_URL=postgresql://postgres:password@%your-ip%:5432/sps
- Install `postgres`
- Create the table sps.flights: `psql -U postgres -d sps -c "CREATE TABLE flights (TRANSACTION_ID SERIAL PRIMARY KEY,YEAR INTEGER,DAY_OF_WEEK INTEGER,FL_DATE DATE,OP_CARRIER_AIRLINE_ID varchar(100),OP_CARRIER_FL_NUM varchar(100),ORIGIN_AIRPORT_ID varchar(100),ORIGIN varchar(100),ORIGIN_CITY_NAME varchar(100),ORIGIN_STATE_NM varchar(100),DEST_AIRPORT_ID varchar(100),DEST varchar(100),DEST_CITY_NAME varchar(100),DEST_STATE_NM varchar(100),DEP_TIME varchar(5),DEP_DELAY FLOAT,ARR_TIME varchar(5),ARR_DELAY FLOAT,CANCELLED FLOAT,AIR_TIME FLOAT);"`
- Import data in the table `sps -c "COPY flights(YEAR,DAY_OF_WEEK,FL_DATE,OP_CARRIER_AIRLINE_ID,OP_CARRIER_FL_NUM,ORIGIN_AIRPORT_ID,ORIGIN,ORIGIN_CITY_NAME,ORIGIN_STATE_NM,DEST_AIRPORT_ID,DEST,DEST_CITY_NAME,DEST_STATE_NM,DEP_TIME,DEP_DELAY,ARR_TIME,ARR_DELAY,CANCELLED,AIR_TIME) FROM '656211699_T_ONTIME_REPORTING.csv' DELIMITER ',' CSV HEADER"`
- Create a new python environment with `python3 -m venv venv`
- Activate the environment with `source venv/bin/activate` (Linux or MAC) or `venv\Scripts\activate` (Windows)
- Install python dependencies with `pip install --no-cache-dir -r requirements.txt`
- Run the application with `flask run --host 0.0.0.0` or `python3 `./run_app.py`
- Open 'localhost:5000' on a browser

---


## Database structure

### `flights`
- transaction_id
- year
- day_of_week
- flight_date
- op_carrier_fl_num
- op_carrier_airline_id
- origin_airport_id
- origin
- origin_city_name
- origin_state_nm
- dest_airport_id
- dest
- dest_city_name
- dest_state_nm
- dep_time
- dep_delay
- arr_time
- arr_delay
- cancelled
- air_time