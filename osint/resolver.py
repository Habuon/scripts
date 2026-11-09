import os
import random
import json
from string import ascii_lowercase
from subprocess import PIPE, STDOUT, Popen
import argparse


def reverse_resolve(ips: list) -> dict:
	result = dict()
	for ip in ips:
		command = f"dig +short -x {ip}"
		with Popen(command, stdout=PIPE, stderr=STDOUT, shell=True) as process:
		    output = process.communicate()[0].decode("utf-8").strip().split("\n")
		result[ip] = [x.rstrip(".") for x in output] 
	return result


def resolve_ips(domains: list) -> dict:
	servers = dict()
	for domain in domains:
		command = f"dig +short a {domain}"
		with Popen(command, stdout=PIPE, stderr=STDOUT, shell=True) as process:
			output = process.communicate()[0].decode("utf-8").strip().split("\n")
		output = output[-1]
		if len(output) == 0:
			continue
		servers[output] = servers.get(output, []) + [domain]
	return servers


def find_domains(base: str, additional_hosts: list) -> list:
	if os.path.isfile(".domains"):
		result = additional_hosts
		with open(".domains", "r") as f:
			for line in f:
				line = line.strip()
				if len(line) == 0:
					continue
				result.append(line) 
		return result

	command = f"subfinder -d {base} -silent"
	with Popen(command, stdout=PIPE, stderr=STDOUT, shell=True) as process:
			output = process.communicate()[0].decode("utf-8").strip().split("\n")
	output = list(set([x for x in output if len(x) != 0] + additional_hosts))
	with open(".domains", "w") as f:
		for line in output:
			print(line, file=f)
	return output


def obtain_org_name(ip: str) -> str:
	command = f"whois {ip}"
	with Popen(command, stdout=PIPE, stderr=STDOUT, shell=True) as process:
			output = process.communicate()[0].decode("utf-8").strip().split("\n")
	for line in output:
		if "descr:" in line and "Static IP assignment" not in line:
			line = line.replace("  ", "")
			_, line = line.split(":", 1)
			if "routes from Slovak Telecom" in line:
				line = "Slovak Telekom"
			return line
	return "N/A"


def identify_dns_wildcard(base):
	possible_wildcards = dict()
	for _ in range(10):
		random_sub = "".join([random.choice(ascii_lowercase) for x in range(10)])
		command = f"dig +short a {random_sub}.{base}"
		with Popen(command, stdout=PIPE, stderr=STDOUT, shell=True) as process:
			output = process.communicate()[0].decode("utf-8").strip().split("\n")
		output = output[-1].strip()
		if len(output) == 0:
			continue
		possible_wildcards[output] = possible_wildcards.get(output, 0) + 1
	return possible_wildcards


def print_heading(text: str, line_width: int) -> None:
	print("-" * line_width)
	text = f"| {text}"
	print(f"{text}{(line_width - len(text) - 1) * ' '}|")
	print("-" * line_width)


def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-b", "--base-host", type=str, help="Base host for which the script will do its business", required=True)
	parser.add_argument("--additional-ips", type=str, help="Additional ips that are part of scope and are obtained by other means separated by comma (e.x. 127.0.0.1,0.0.0.0)", required=False)
	parser.add_argument("--additional-hosts", type=str, help="Additional hosts that are part of scope and are obtained by other means separated by comma (e.x. localhost,loopback)", required=False)
	args = parser.parse_args()
	return args

	
def main():
	line_width = 200

	# Args
	args = parse_args()
	base = args.base_host
	additional_ips = [] if args.additional_ips is None else args.additional_ips.split(",")
	additional_hosts = [] if args.additional_hosts is None else args.additional_hosts.split(",")

	# Find all subdomains by passive means
	print(f"[*] Running subfinder ... ", end="", flush=True)
	domains = find_domains(base, additional_hosts=additional_hosts)
	print(f"found {len(domains)} domains")

	# Determine possible DNS wildcards
	possible_wildcards = identify_dns_wildcard(base)
	sorted_wildcards = sorted(list(possible_wildcards.keys()), key=lambda x: possible_wildcards[x], reverse=True)

	if len(sorted_wildcards) != 0:
		print_heading("Possible DNS Wildcards", line_width)
		for possible_wildcard in sorted_wildcards:
			print(f"[*] Server with IP {possible_wildcard} is possible DNS wildcard (tested with 10 randomly generated subdomains and got {possible_wildcards[possible_wildcard]}/10)")
		print_heading("Possible DNS Wildcards", line_width)
	
	# Resolve all IPs of found domains
	servers = resolve_ips(domains)
	
	all_ips = list(servers.keys()) + additional_ips

	# Try dig -x to reverse resolve possible domains for each IP
	reverse = reverse_resolve(all_ips)

	orgs = dict()
	if len(all_ips) != 0:
		print_heading("Running WHOIS", line_width)
		for ip in all_ips:
			org = obtain_org_name(ip)
			orgs[org] = orgs.get(org, []) + [ip]
		print(json.dumps(orgs, indent=4), flush=True)
		print_heading("Running WHOIS", line_width)

	result = {ip: list(set([x for x in servers.get(ip, []) + reverse.get(ip, []) if len(x) != 0])) for ip in all_ips}
	print(json.dumps(result, indent=4), flush=True)
	

if __name__ == "__main__":
	main()
