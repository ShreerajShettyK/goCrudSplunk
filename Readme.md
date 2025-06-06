# GoLang CRUD Application with Splunk Logging
 
## Microservice Setup:
This microservice is designed to expose some API endpoints for user-management-service which is integrated with splunk for log analysis. Follow the instructions below to set up your development environment and run the code.
 
References:
- [Official REST splunk](https://docs.splunk.com/Documentation/Splunk/9.4.0/RESTREF/RESTknowledge#data.2Fui.2Fviews.2F.7Bname.7D)
 
Note: Splunk version is 9.4.0
 

### Getting Started
This is a guide to using this Golang project.
 
 
### Requirements
- Go installed on your system. You can download it from Go's official website.
- Access to splunk server and Splunk REST API with necessary credentials.
 
 
### Instructions for local setup:
- `.env.sample` sample file:
    ~~~txt
    PORT=8084
    MONGOURL=mongodb+srv://task3-dummy:wertyuioiuytre@cluster0.0elhpdy.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0
    DB_NAME=cluster0

    JWT_SECRET=rtyuioiuytrertyuioiuytrew
    JWT_EXPIRATION_IN_SECONDS=3600*24*7

    SPLUNKURL   = http://localhost:8088/services/collector
    SPLUNKHECTOKEN = paste_hec_token
    SPLUNKINDEX = index_name
    SPLUNK_HOST=localhost
    SPLUNK_SOURCE=http-event-logs
    SPLUNK_SOURCETYPE=logrus_go_app
    ~~~
    Note:Ensure all variables are correctly set in your .env file before running the application.
    Modify the placeholders in the env file as per your environment requirements.
 
- Run the below command to execute the program:
    ~~~bash
    go run main.go
    ~~~
 
