# Fawkes Mythic C2 Agent

<img src="agent_icons/fawkes.svg" width="100" />

Fawkes is my attempt at a Mythic C2 Agent. Fawkes is a golang based agent that will have cross platform agent capabilities, but currently operates on Windows. 

## Installation
To install Fawkes, you'll need Mythic installed on a remote computer. You can find installation instructions for Mythic at the [Mythic project page](https://github.com/its-a-feature/Mythic/).

From the Mythic install directory:

```
./mythic-cli install github https://github.com/galoryber/fawkes
```

## Commands Manual Quick Reference

Command | Syntax                                                                                                                | Description
------- |-----------------------------------------------------------------------------------------------------------------------| -----------
exit | `exit`                                                                                                                   | Task agent to exit.
ls | `ls [path]`                                                                                                        | List files and folders in `[path]`. Defaults to current working directory.
pwd | `pwd`                                                                                                                     | Print working directory.
sleep | `sleep [seconds] [jitter] -> sleep 10 50`                                                                                                       | Set the callback interval in seconds and jitter percentage .



## Supported C2 Profiles

### [HTTP Profile](https://github.com/MythicC2Profiles/http)

The HTTP profile calls back to the Mythic server over the basic, non-dynamic profile.


## Thanks
Everything I know about Mythic Agents came from stealing code and ideas from the Merlin and Freyja agents. 

# References
https://openclipart.org/detail/229408/colorful-phoenix-line-art-12
https://openclipart.org/detail/228829/phoenix-line-art