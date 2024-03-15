# IOC-Enricher
Python program designed to perform IP reputation lookup for a list of using the VirusTotal API and write results in a csv file.

Prerequisites for running the Python program:

    Python: Ensure Python is installed on your system (Python 3 recommended).

    Required Libraries: Install the requests and tqdm libraries using pip.

    VirusTotal API Key: Obtain an API key from VirusTotal.

    Input File: Prepare a text file with a list of IP addresses.

Run the program by executing the following command:
```
python3 lookup.py input_file.txt
```


Working:

	- The program then establishes a connection with the VirusTotal API endpoint for retrieving IP address lookups.
	- Sets up the necessary headers and specifies the format for accepting JSON response data.
	- Depending on whether the IP address is deemed malicious or not, the program writes the IP address, country, and status (malicious or undetected) to the CSV file.
 	- If an error occurs during the request, the program writes an error message to the CSV file.
  	- Throughout the IP address processing, the program utilizes the `tqdm` library to display a progress bar indicating the progress of the scan.
