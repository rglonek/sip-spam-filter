# SIP-Spam-Filter

# Overview

This is a simple SIP spam filter that blocks incoming calls from known spam numbers, by accepting calls from the blacklist and dropping them after 1 second.

# Configuration

This is the full yaml config file. The values shown below are the defaults applied when a value is not specified in the config file.

```yaml
log_level: 4             # Log level 0=none, 1=critical, 2=error, 3=warning, 4=info, 5=debug, 6=detail
local_addr: "0.0.0.0:0"  # Local address to bind to
country_code: "44"       # Country code to use for international numbers
sip:
  user: ""                # SIP username
  password: ""            # SIP password 
  host: ""                # SIP server hostname
  port: 5060              # SIP server port
  expiry: 500s            # SIP registration expiry
audit_files: # if any of these exist, audit log will be written to them
  blocked_numbers: "" # path to file, format: timestamp,number,blocklist_file_name,blocklist_file_line_number (timestamp in RFC3339 format)
  allowed_numbers: "" # path to file, format: timestamp,number (timestamp in RFC3339 format)
spam:
  try_to_answer_delay: 100ms       # Time to wait before trying to answer spam calls (SIP 100->trying)
  answer_delay: 100ms              # Time to wait before answering spam calls (SIP 183->answered)
  hangup_delay: 1s                 # Time to wait before hanging up spam calls (SIP 180->hangup)
  blacklist_paths:                 # Paths to blacklist files/directories
    #- "./blacklists/"
    #- "./blacklist.txt"
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
6 | Detail | Trace messages for troubleshooting

The log level will also be applied to the SIP library.

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
try_to_answer_delay | Millseconds to wait before sending a "trying to answer" message
answer_delay | Millseconds to wait after sending "trying to answer", before answering the call
hangup_delay | Milliseconds to wait before hanging up spam calls after accepting the call
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

# Benchmark

## Test machine

```
goos: darwin
goarch: amd64
pkg: sip-spam-filter
cpu: Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz
```

## Summary

Tested worst-case speed, including long comments and average-sized filenames. Results summary: all tests completed way below 1 millsecond, up to `100'000'000` entries tested. In essence, while we benchmarked many possible results, the fact we are way below 1 millisecond for searches means we are extremely fast for any purpose.

Lookups do not allocate any extra memory during a lookup.

## Analysis

In general, it is better to have more entries per file, less files. For example, looking up total 1 million results over 100 files is 12x faster than looking up 1 million total split over over 1000 files.

Similarly, looking up 10 million results split over 10 files takes 10x less time than looking up 1 million results split over 100 files.

This is because the search uses one map per file to keep track of which blacklist the number appeared in. This result may also be slightly inaccurate as the results do not take into consideration possible matches, or variations in indexed searches. This test assumes the search has to navigate every part of every branch of every map tree.

## Data

Files | Entries per file | Total Entries | Result - microseconds/lookup
--- | --- | --- | ---
100 | 1000 | 100'000 | 1.343
100 | 5000 | 500'000 | 1.660
100 | 10000 | 1'000'000 | 1.563
1000 | 100 | 100'000 | 23.323
1000 | 500 | 500'000 | 15.650
1000 | 1000 | 1'000'000 | 19.448
1000 | 5000 | 5'000'000 | 25.199
1000 | 10000 | 10'000'000 | 26.822
10000 | 10000 | 100'000'000 | 368.848
10 | 1000000 | 10'000'000 | 0.127
100 | 1000000 | 100'000'000 | 1.585
10 | 10000000 | 100'000'000 | 0.139

## Notes on memory

Reloading of the blacklists actually takes place separately from when the list is running. The reload means that a new blacklist is created in memory, and then the delay only happens as the old blacklist pointer is replaced with the new one. Speed-wise it means we do not care how long it takes to load the blacklist on refresh, as the actual functionality blip takes a few nanoseconds. Memory utilization on the other hand doubles during the refresh.

To mitigate issues with multiple refreshes, the refreshes may be queued (this queue is currently unlimited, so check logs before doing another refresh with SIGUSR1), but they will be executed one at a time.
