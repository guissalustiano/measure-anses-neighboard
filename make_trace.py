import sys
import csv


MAX_TTL = 24

INPUT_FORMAT = ['destination', 'ttl', 'id', 'ip', 'send_at', 'received_at', 'terminator']
DESTINATION = 0
TTL = 1
ID = 2
IP = 3
SEND_AT = 5 # SEND_AT seems to be switched with RECEIVED_AT 
RECEIVED_AT = 4
TERMINATOR = 6

def make_traces(input_path):
    traces = {}
    with open(input_path, newline='') as input_csv:
        input_reader = csv.reader(input_csv)
        if next(input_reader) != INPUT_FORMAT:
            print(f"Expected input to be a csv with format: {INPUT_FORMAT}", file=sys.stderr)
            exit(-1)
                
        for row in input_reader:
            if row[DESTINATION] not in traces:
                #one more than MAX_TTL to indicate reachability
                traces[row[DESTINATION]] = [None] * (MAX_TTL+1)
            try:
                traces[row[DESTINATION]][int(row[TTL])-1] = (row[IP], f"{int(row[RECEIVED_AT]) - int(row[SEND_AT])}ms") 
            except Exception as e:
               pass 
            if row[TERMINATOR] == "true":
                traces[row[DESTINATION]] = traces[row[DESTINATION]][:int(row[TTL])]
    return traces
        
if __name__ == "__main__":
    input_path = None
    try:
        input_path = sys.argv[1]
    except IndexError:
        print(f"Usage: python {sys.argv[0]} [path_to_input.csv] > [path_to_output.csv]", file=sys.stderr)
        exit(-1)

    print("target\ttrace")
    for target, trace in make_traces(input_path).items():
        print(f"{target}\t{trace}")

