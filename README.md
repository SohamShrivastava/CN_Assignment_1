# CN_Assignment_1

### Setup

1. **Clone the github repoistry**

2. **Install the requirements.txt**
   
   ```bash
   python install -r  requirements.txt
   
3. **Then, First run the server.py**
   
   You will see like this output confirming server is running:
   
   server is listening on 127.0.0.1:12345
   
4. **Before running the client.py, make sure following variables are set properly:**
   
   a. pcap_file: Make sure you had set correct path of your input pcap file
   
   b. server_ip: Should be set to 127.0.0.1 (for running locally)
   
   c. server_port: 12345

5. **Run the client.py**

### Expected Output
1. **Server Terminal**: You will see log messages for each connection received and the IP address it resolved for the query.

2. **Client Terminal**: The client will print the status of each query it sends. After processing all queries, it will display a final summary table in the console.

3. **CSV Report**: A file named dns_report.csv will be created in the project directory. This file contains a tabular report of all the processed DNS queries, including the custom header, domain name, and the final resolved IP address.
