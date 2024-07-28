##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

# Installation-wide salt value that is used in some digest hashes, e.g., for
# the creation of file IDs. Please change this to a hard to guess value.
redef digest_salt = "nids";

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# Estimate and log capture loss.
@load misc/capture-loss

# Enable logging of memory, packet and lag statistics.
@load misc/stats

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
@load frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
@load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
@load protocols/ftp/detect

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
@load protocols/ssl/validate-certs

# This script prevents the logging of SSL CA certificates in x509.log
# @load protocols/ssl/log-hostcerts-only

# If you have GeoIP support built in, do some geographic detections and
# logging for SSH traffic.
@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
@load protocols/http/detect-sqli

#### Network File Handling ####

# Enable MD5 and SHA1 hashing for all files.
@load frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
@load frameworks/files/detect-MHR

# Extend email alerting to include hostnames
@load policy/frameworks/notice/extend-email/hostnames

# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
@load policy/protocols/ssl/heartbleed

# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
@load policy/protocols/conn/vlan-logging

# Uncomment the following line to enable logging of link-layer addresses. Enabling
# this adds the link-layer address for each connection endpoint to the conn.log file.
@load policy/protocols/conn/mac-logging

# Uncomment this to source zkg's package state
# @load packages

#Custom conn geoip enrichment
@load geodata/conn-add-geodata.zeek

# Log all plain-text http/ftp passwords
@load passwords/log-passwords.zeek

#Extract files from network traffic with Zeek
@load file-extraction

#Adds cluster node name to logs.
@load add-node-names

#Watch SMB transactions for files whose filename matches patterns known to be used by ransomware
@load detect-ransomware-filenames

#Checks for HTTP anomalies typically used for attacking
@load zeek-httpattacks

#Add all HTTP headers and values to the HTTP log.
@load zeek-log-all-http-headers

#Find and log long-lived connections into a "conn_long" log.
@load zeek-long-connections

#Sniffpass will alert on cleartext passwords discovered in HTTP POST requests
@load zeek-sniffpass

#BZAR - Bro/Zeek ATT&CK-based Analytics and Reporting.
@load bzar

#Below section to wite log in json format
@load tuning/json-logs
redef LogAscii::use_json=T;

# Kafka Plugin
@load packages/zeek-kafka
redef Kafka::send_all_active_logs = T;
redef Kafka::tag_json = T;
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "localhost:29092"
);
redef Known::cert_tracking = ALL_HOSTS;
redef Software::asset_tracking = ALL_HOSTS;
# Default is JSON::TS_EPOCH. Other options are JSON::TS_MILLIS and JSON::TS_ISO8601.
redef Kafka::json_timestamps = JSON::TS_MILLIS;

module Conn;

export {
	redef record Conn::Info += {
		## To get tenant id or branch id or client id.
		tenant_id: string &optional &log;		
	};
}

# Static value differs based on zeek client network
global tenant_id ="companyname_branch_1";

# Function to get the customer ID from the hostname
function get_tenant_id(): string {
    return fmt("tenant_%s", tenant_id);
}

event connection_state_remove(c: connection)
{
    c$conn$tenant_id =get_tenant_id();
}

