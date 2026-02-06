+++
title = "sleep"
chapter = false
weight = 103
hidden = false
+++

## Summary

Update the agent's callback interval and jitter percentage.

### Arguments

#### interval
Sleep time in seconds.

#### jitter (optional)
Jitter percentage (0-100). Controls the randomness of the callback interval.

## Usage
```
sleep [seconds] [jitter%]
```

Example
```
sleep 30
sleep 60 20
```
