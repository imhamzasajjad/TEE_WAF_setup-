import os
import requests
import csv
from datetime import datetime
import time
import random
from sqlfuzzer import SqlFuzzer  # Import your fuzzer class

# Function to wait until services are ready (if needed)
def wait_until_services_ready():
    time.sleep(5)  # Adjust the delay as needed based on your Docker service startup time

# Function to send request to server and return the results
def send_request(payload):
    url = 'http://server:5000/request'  # Adjust server URL as needed
    data = {
        'payload': payload.strip()  # Remove any trailing newline characters
    }
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            waf_status_code = response.json().get('WAF_status_code', 'Unknown')
            ml_status_code = response.json().get('ML_status_code', 'Unknown')
        else:
            waf_status_code = response.status_code
            ml_status_code = 'Error'
        
        # Return status codes
        return waf_status_code, ml_status_code
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return 'Error: Connection failed', 'Error: Connection failed'

# Function to determine TP, TN, FP, FN
def determine_metrics(original_status, predicted_status):
    if original_status == 403:
        if predicted_status == 403:
            return 'TP'
        else:
            return 'FN'
    else:
        if predicted_status == 200:
            return 'TN'
        else:
            return 'FP'

# Function to determine if the predictions from WAF and ML match
def determine_combined_result(original_status, waf_status, ml_status):
    waf_metric = determine_metrics(original_status, waf_status)
    ml_metric = determine_metrics(original_status, ml_status)
    
    if (waf_metric in ['TP', 'TN']) and (ml_metric in ['TP', 'TN']):
        return 'both_correct'
    elif (waf_metric in ['FP', 'FN']) and (ml_metric in ['FP', 'FN']):
        return 'both_incorrect'
    elif (waf_metric in ['TP', 'TN']) and (ml_metric in ['FP', 'FN']):
        return 'waf_correct_ml_incorrect'
    else:
        return 'waf_incorrect_ml_correct'

# Function to run the main process
def main():
    wait_until_services_ready()  # Wait for services to start up

    # Get environment variables for the number of random samples and fuzzing rounds
    num_samples = int(os.getenv('NUM_SAMPLES', 10))  # Default to 10 if not set
    num_fuzzing_rounds = int(os.getenv('NUM_FUZZING_ROUNDS', 5))  # Default to 5 if not set

    payloads_file = 'payloads.csv'
    
    with open(payloads_file, mode='r') as file:
        reader = csv.reader(file)
        headers = next(reader)  # Read the header row
        payloads = list(reader)  # Read the payloads

    # Select a random sample of payloads
    sample_payloads = random.sample(payloads, min(num_samples, len(payloads)))

    with open('logs/client_logs.csv', mode='w', newline='') as log_file:
        writer = csv.writer(log_file)
        # Write the header row
        header = ['Sr NO.', 'Original Timestamp', 'Payload', 'Original Status', 'WAF Status', 'ML Status', 'Combined Result']
        for i in range(1, num_fuzzing_rounds + 1):
            header.extend([f'Fuzzed Payload {i}', f'Fuzzed Timestamp {i}', f'WAF Status {i}', f'ML Status {i}', f'Combined Result {i}'])
        writer.writerow(header)
        
        serial_number = 1
        
        # Initialize counters for WAF and ML metrics
        waf_tp, waf_tn, waf_fp, waf_fn = 0, 0, 0, 0
        ml_tp, ml_tn, ml_fp, ml_fn = 0, 0, 0, 0

        # Initialize counters for the confusion matrix
        both_correct = 0
        both_incorrect = 0
        waf_correct_ml_incorrect = 0
        waf_incorrect_ml_correct = 0

        for idx, row in enumerate(sample_payloads, start=1):
            original_payload = row[0]
            original_status = int(row[1])  # Ensure original status is an integer
            original_timestamp = datetime.now().isoformat()
            waf_status_code, ml_status_code = send_request(original_payload)  # Send original payload
            
            # Determine WAF and ML metrics for the original payload
            waf_metric = determine_metrics(original_status, waf_status_code)
            ml_metric = determine_metrics(original_status, ml_status_code)
            
            # Update WAF metrics
            if waf_metric == 'TP':
                waf_tp += 1
            elif waf_metric == 'TN':
                waf_tn += 1
            elif waf_metric == 'FP':
                waf_fp += 1
            elif waf_metric == 'FN':
                waf_fn += 1
            
            # Update ML metrics
            if ml_metric == 'TP':
                ml_tp += 1
            elif ml_metric == 'TN':
                ml_tn += 1
            elif ml_metric == 'FP':
                ml_fp += 1
            elif ml_metric == 'FN':
                ml_fn += 1

            # Determine combined result for original payload
            combined_result = determine_combined_result(original_status, waf_status_code, ml_status_code)
            if combined_result == 'both_correct':
                both_correct += 1
            elif combined_result == 'both_incorrect':
                both_incorrect += 1
            elif combined_result == 'waf_correct_ml_incorrect':
                waf_correct_ml_incorrect += 1
            elif combined_result == 'waf_incorrect_ml_correct':
                waf_incorrect_ml_correct += 1

            # Log the result
            log_entry = [serial_number, original_timestamp, original_payload, original_status, waf_status_code, ml_status_code, combined_result]
            
            # Generate and send fuzzed payloads
            fuzzer = SqlFuzzer(original_payload)  # Initialize fuzzer with the original payload
            for i in range(1, num_fuzzing_rounds + 1):
                fuzzed_payload = fuzzer.fuzz()  # Fuzz the payload
                fuzzed_timestamp = datetime.now().isoformat()
                fuzzed_waf_status_code, fuzzed_ml_status_code = send_request(fuzzed_payload)  # Send fuzzed payload
                
                # Determine WAF and ML metrics for fuzzed payload
                fuzzed_waf_metric = determine_metrics(original_status, fuzzed_waf_status_code)
                fuzzed_ml_metric = determine_metrics(original_status, fuzzed_ml_status_code)
                
                # Update WAF metrics
                if fuzzed_waf_metric == 'TP':
                    waf_tp += 1
                elif fuzzed_waf_metric == 'TN':
                    waf_tn += 1
                elif fuzzed_waf_metric == 'FP':
                    waf_fp += 1
                elif fuzzed_waf_metric == 'FN':
                    waf_fn += 1

                # Update ML metrics
                if fuzzed_ml_metric == 'TP':
                    ml_tp += 1
                elif fuzzed_ml_metric == 'TN':
                    ml_tn += 1
                elif fuzzed_ml_metric == 'FP':
                    ml_fp += 1
                elif fuzzed_ml_metric == 'FN':
                    ml_fn += 1

                # Determine combined result for fuzzed payload
                fuzzed_combined_result = determine_combined_result(original_status, fuzzed_waf_status_code, fuzzed_ml_status_code)
                if fuzzed_combined_result == 'both_correct':
                    both_correct += 1
                elif fuzzed_combined_result == 'both_incorrect':
                    both_incorrect += 1
                elif fuzzed_combined_result == 'waf_correct_ml_incorrect':
                    waf_correct_ml_incorrect += 1
                elif fuzzed_combined_result == 'waf_incorrect_ml_correct':
                    waf_incorrect_ml_correct += 1

                log_entry.extend([fuzzed_payload, fuzzed_timestamp, fuzzed_waf_status_code, fuzzed_ml_status_code, fuzzed_combined_result])
                
                # Pause between requests if needed
                time.sleep(1)
            
            writer.writerow(log_entry)  # Write the log entry
            serial_number += 1

        # Save overall results to the log file
        writer.writerow([])
        writer.writerow(['Overall Results'])
        writer.writerow(['WAF TP', waf_tp])
        writer.writerow(['WAF TN', waf_tn])
        writer.writerow(['WAF FP', waf_fp])
        writer.writerow(['WAF FN', waf_fn])
        writer.writerow(['ML TP', ml_tp])
        writer.writerow(['ML TN', ml_tn])
        writer.writerow(['ML FP', ml_fp])
        writer.writerow(['ML FN', ml_fn])

        # Save combined prediction results to the log file as a 2x2 confusion matrix
        writer.writerow([])
        writer.writerow(['Combined Results (2x2 Matrix)'])
        writer.writerow(['', 'WAF Correct', 'WAF Incorrect'])
        writer.writerow(['ML Correct', both_correct, waf_incorrect_ml_correct])
        writer.writerow(['ML Incorrect', waf_correct_ml_incorrect, both_incorrect])

        # Print the combined prediction results as a 2x2 confusion matrix
        print("\nCombined Results (2x2 Matrix):")
        print(f"{'':<15}{'WAF Correct':<15}{'WAF Incorrect':<15}")
        print(f"{'ML Correct':<15}{both_correct:<15}{waf_incorrect_ml_correct:<15}")
        print(f"{'ML Incorrect':<15}{waf_correct_ml_incorrect:<15}{both_incorrect:<15}")

if __name__ == "__main__":
    main()
