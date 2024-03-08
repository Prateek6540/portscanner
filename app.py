import io
import csv
from flask import Flask, render_template, request, send_file
import socket
import nmap

app = Flask(__name__)

def scan_ports(target_ip, scan_type):
    open_ports = {}
    closed_ports = {}
    try:
        nm = nmap.PortScanner()

        if scan_type == '1':
            nm.scan(target_ip, arguments='-p 1-1000 --open')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]['name']
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports[port] = service
                        else:
                            closed_ports[port] = service

        
            for port in range(1,1000):
                if port not in open_ports and port not in closed_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.11)
                    result = sock.connect_ex((target_ip, port))
                    try:
                        service = socket.getservbyport(port)
                    except (socket.error, OSError, socket.herror, socket.gaierror):
                        service = "Unknown"
                    
                    if result == 0:
                        open_ports[port] = service
                    else:
                        closed_ports[port] = service
                    sock.close()
        elif scan_type == '2':
            nm.scan(target_ip, arguments='-p 1-65535 --open')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]['name']
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports[port] = service
                        else:
                            closed_ports[port] = service

        
            for port in range(1,65535):
                if port not in open_ports and port not in closed_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.11)
                    result = sock.connect_ex((target_ip, port))
                    try:
                        service = socket.getservbyport(port)
                    except (socket.error, OSError, socket.herror, socket.gaierror):
                        service = "Unknown"
                    
                    if result == 0:
                        open_ports[port] = service
                    else:
                        closed_ports[port] = service
                    sock.close()
        elif scan_type == '3':
            specific_port = request.form['specific_port']
            nm.scan(target_ip, arguments=f'-p {specific_port} --open')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]['name']
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports[port] = service
                        else:
                            closed_ports[port] = service
                if int(specific_port)  not in open_ports and int(specific_port)  not in closed_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.11)
                    result = sock.connect_ex((target_ip, port))
                    try:
                        service = socket.getservbyport(port)
                    except (socket.error, OSError, socket.herror, socket.gaierror):
                        service = "Unknown"
                    
                    if result == 0:
                        open_ports[port] = service
                    else:
                        closed_ports[port] = service
                    sock.close()

        
            
                
        elif scan_type == '4':
            start_port = request.form['start_port']
            end_port = request.form['end_port']
            nm.scan(target_ip, arguments=f'-p {start_port}-{end_port} --open')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]['name']
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports[port] = service
                        else:
                            closed_ports[port] = service

        
            for port in range(int(start_port),int(end_port)):
                if port not in open_ports and port not in closed_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.11)
                    result = sock.connect_ex((target_ip, port))
                    try:
                        service = socket.getservbyport(port)
                    except (socket.error, OSError, socket.herror, socket.gaierror):
                        service = "Unknown"
                    
                    if result == 0:
                        open_ports[port] = service
                    else:
                        closed_ports[port] = service
                    sock.close()
        else:
            raise ValueError("Invalid Scan Type")

        
    except Exception as e:
        print(f"Error during port scan: {e}")

    return open_ports, closed_ports


def generate_csv_file(open_ports, closed_ports):
    output = io.StringIO()
    writer = csv.writer(output)

    # Write headers
    writer.writerow(['Port', 'Service', 'Status'])

    # Write open ports
    for port, service in open_ports.items():
        writer.writerow([port, service, 'Open'])

    # Write closed ports
    for port, service in closed_ports.items():
        writer.writerow([port, service, 'Closed'])

    return output.getvalue()

from flask import redirect
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/agree', methods=['POST'])
def agree():
    agreed = request.form.get('agree')
    if agreed:
        return redirect('/home')

    return render_template('error.html', error="You must agree to the terms and conditions to proceed.")

@app.route('/home')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        target_type = request.form['target_type']
        target = request.form['target']
        scan_type = request.form['scan_type'] 

        if target_type == 'url':
            target_ip = socket.gethostbyname(target)
        else:
            target_ip = target

        open_ports, closed_ports = scan_ports(target_ip, scan_type)

        csv_data = generate_csv_file(open_ports, closed_ports)

        return send_file(
            io.BytesIO(csv_data.encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='port_scan_results.csv'
        )

    except Exception as e:
        return render_template('error.html', error=f"An error occurred: {e}")

if __name__ == "__main__":
    app.run(debug=True)
