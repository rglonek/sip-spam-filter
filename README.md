# SIP-Spam-Filter

# Overview

This is a simple SIP spam filter that blocks incoming calls from known spam numbers, by accepting calls from the blacklist and dropping them after 1 second.

# Configuration

```yaml
log_level: 6            # Log level 0=none, 1=critical, 2=error, 3=warning, 4=info, 5=debug, 6=detail
local_addr: "0.0.0.0:0"  # Local address to bind to - 0.0.0.0:0 means any address, random port; this is normally ok for most cases
country_code: "44"       # Country code to use for international numbers
sip:
  user: "SIPUSER"         # SIP username
  password: "SIPPASSWORD" # SIP password 
  host: "SIPHOST"         # SIP server hostname
  port: 5060              # SIP server port
  expiry_seconds: 500     # SIP registration expiry seconds - this is usually provided by the SIP server, and you want this number to be below so that registration can be renewed
audit_files: # if any of these exist, audit log will be written to them
  blocked_numbers: "./blocked_numbers.log" # format: timestamp,number,blocklist_file_name,blocklist_file_line_number (timestamp in RFC3339 format)
  allowed_numbers: "./allowed_numbers.log" # format: timestamp,number (timestamp in RFC3339 format)
spam:
  sleep_seconds: 1      # Seconds to wait before hanging up spam calls
  blacklist_paths:      # Paths to blacklist files/directories
    - "./blacklist.txt"
    - "./blacklists/"
```

## Log Levels

Level | Name | Description
--- | --- | ---
0 | None | No logging
1 | Critical | Critical errors resulting in a crash
2 | Error | Errors
3 | Warning | Warnings
4 | Info | General information
5 | Debug | Debug messages from them spam filter processing
6 | Detail | All non-critical messages from the SIP library itself

## Local address and country code

The local address is the address and port that the spam filter will listen on. The `0.0.0.0:0` is normally ok as it means any address, random port.

The country code is the country code to use for international numbers. This is normally the country code of the SIP server or the number that is registering with the SIP server. The country code is used to convert the caller ID number to E.164 format for the blacklist lookup. It should be just the country code digits, without a `00` or `+` prefix.

## SIP configuration

The SIP configuration is used to configure the SIP server that the spam filter will use to register with.

## Audit Files

The audit files are written to the location specified in the config file. If the file does not exist, it will be created. If the file exists, it will be appended to.

If the audit files are not specified in the config file, then no audit log will be written.

Audit File | Format | Timestamp Format
--- | --- | ---
blocked_numbers.log | timestamp,number,blocklist_file_name,blocklist_file_line_number | RFC3339
allowed_numbers.log | timestamp,number | RFC3339

## Spam

The spam section is used to configure the spam filter.

Parameter | Description
--- | ---
sleep_seconds | Seconds to wait before hanging up spam calls after accepting the call
blacklist_paths | Paths to blacklist files/directories

## Blacklist

The blacklist paths is a list of files or directories that contain the blacklist numbers. The directories are checked recursively.

Each line in the blacklist files contains a single number.

The numbers should be in E.164 format, meaning they should start with a + and then the country code and then the number (see example blacklist.txt in this repo).

# Signals

The spam filter will listen for the following signals:

Signal | Description
--- | ---
SIGHUP | Reopen the audit files (useful for log rotation or file deletion)
SIGUSR1 | Reload the blacklist (useful for adding new numbers to the blacklist or removing numbers from the blacklist)
SIGINT | Shutdown the spam filter
SIGTERM | Shutdown the spam filter

# SIP

* The spam filter will listen for SIP requests on the local address and port specified in the config file.
* The spam filter will respond to INVITE requests with a 200 OK and a 1 second delay before hanging up the call.
* The spam filter will not respond to any other SIP requests on the connection.
* The spam filter will not send any SIP requests to the SIP server.

# Usage

## Download prebuilt binaries

Head over the the [releases page](https://github.com/rglonek/sip-spam-filter/releases) and download the latest release for your platform.

## Build from source

```bash
go build -o spam-filter main.go
```

## Run

```bash
./spam-filter --config config.yaml
```

The spam filter can be run from docker or as a systemd service.

## Reload Blacklist

```bash
kill -USR1 $(pidof spam-filter)
```

## Reopen Audit Files

```bash
kill -SIGHUP $(pidof spam-filter)
```
