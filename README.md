\# MAV Raiders



\*\*Security Analysis and Exploitation of MAVLink-Based Drone Communications\*\*



MAV Raiders is a university cybersecurity project focused on the security analysis of MAVLink-based drone communications.



The project investigates the attack surface exposed by MAVLink communication between PX4 simulated UAVs and a Ground Control Station (QGroundControl), with particular attention to reconnaissance, packet inspection, message injection, fuzzing, denial-of-service conditions, man-in-the-middle attacks, and MAVLink signing.



All experiments were conducted in a controlled and authorized simulation environment using PX4 SITL.



\## Project Goals



The project aims to study the security implications of MAVLink-based communication and evaluate how an attacker with network access could interact with or interfere with UAV communication.



The implemented tools cover several phases of a security assessment:



\- MAVLink endpoint reconnaissance

\- MAVLink traffic inspection

\- vulnerability testing

\- message and command injection

\- protocol fuzzing

\- parameter manipulation

\- denial-of-service and crash experiments

\- MAVProxy-based traffic interception

\- man-in-the-middle attacks

\- MAVLink signing security analysis



\## Test Environment



The project was developed and tested using a Windows + WSL2 environment.



\### Windows



\- QGroundControl



\### WSL2 / Ubuntu



\- PX4 SITL

\- Python 3.12.3

\- pymavlink 2.4.49

\- Scapy 2.7.0

\- Colorama 0.4.6

\- Tabulate 0.10.0

\- MAVProxy 1.8.74



Multiple PX4 SITL instances were used to reproduce a small multi-drone environment.



\## Architecture



A simplified representation of the experimental environment is:



```text

&#x20;                MAVLink / UDP



&#x20;  +-------------+       +------------------+

&#x20;  | PX4 SITL #1 |------>|

&#x20;  +-------------+       |

&#x20;                        |

&#x20;  +-------------+       |   Analysis /

&#x20;  | PX4 SITL #2 |------>|   Attack Tools

&#x20;  +-------------+       |

&#x20;                        |

&#x20;  +-------------+       |

&#x20;  | PX4 SITL #3 |------>|

&#x20;  +-------------+       +---------+--------+

&#x20;                                  |

&#x20;                                  | MAVLink

&#x20;                                  v

&#x20;                          +---------------+

&#x20;                          | QGroundControl|

&#x20;                          +---------------+



For the MITM experiments, MAVProxy is positioned between the PX4 instances and QGroundControl, allowing MAVLink traffic to be observed and manipulated in the controlled test environment.

Repository Structure

.

├── recon.py

├── mavlink\_inspector.py

├── vuln\_tester.py

├── fuzzer.py

├── inject\_qgc.py

├── inject\_drones\_v2.py

├── inject\_drones\_v3.py

├── qgc\_param\_crash.py

├── px4\_crash\_exploits.py

├── mavproxy\_hijack.py

├── mavlink\_mitm\_attack.py

├── threat\_c\_signing\_bypass.py

├── launch\_mitm.sh

├── requirements.txt

│

├── docs/

│   ├── attack\_plan.md

│   ├── demo\_commands.txt

│   └── presentation\_notes.txt

│

└── reports/

&#x20;   ├── report\_single\_drone.txt

&#x20;   └── report\_three\_drones.txt



Tools

Reconnaissance

recon.py

Performs reconnaissance of the MAVLink environment and helps identify reachable MAVLink endpoints and UAVs.

MAVLink Inspector

mavlink\_inspector.py

Inspects MAVLink traffic and extracts information useful for understanding the communication occurring between the simulated UAVs and the ground station.

Vulnerability Tester

vuln\_tester.py

Automates a set of security checks against the MAVLink environment and produces reports that can be used to evaluate the observed attack surface.

MAVLink Fuzzer

fuzzer.py

Generates and sends test inputs to evaluate how MAVLink endpoints react to malformed, unexpected, or unusual messages in the controlled simulation environment.

Message Injection

inject\_qgc.py

Explores message injection against the Ground Control Station side of the experimental environment.

inject\_drones\_v2.py and inject\_drones\_v3.py

Contain the multi-drone injection experiments developed during the project.

Parameter and Availability Testing

qgc\_param\_crash.py

Investigates the effects of parameter-related MAVLink interactions on the Ground Control Station in the test environment.

px4\_crash\_exploits.py

Contains experimental availability and robustness tests targeting the simulated PX4 environment.

MAVProxy Hijacking

mavproxy\_hijack.py

Supports experiments in which MAVProxy is used to intercept MAVLink communication and interact with the traffic flowing between simulated UAVs and QGroundControl.

Man-in-the-Middle

mavlink\_mitm\_attack.py

Implements the project's MAVLink man-in-the-middle experiment.

launch\_mitm.sh

Sets up the MAVProxy-based MITM environment used with the PX4 SITL instances and QGroundControl.

MAVLink Signing Analysis

threat\_c\_signing\_bypass.py

Contains the experiments related to MAVLink signing and the corresponding threat scenario investigated during the project.

Installation

The recommended environment is WSL2/Ubuntu.

Clone the repository:

git clone <repository-url>

cd <repository-name>



Create a Python virtual environment:

python3 -m venv .venv

source .venv/bin/activate



Install the Python dependencies:

python3 -m pip install --upgrade pip

pip install -r requirements.txt



The project was tested with Python 3.12.3.

Dependencies

The reference environment used:

pymavlink==2.4.49

scapy==2.7.0

colorama==0.4.6

tabulate==0.10.0

MAVProxy==1.8.74



Additional components required to reproduce the complete experimental environment include:

\- PX4 SITL

\- QGroundControl

\- WSL2 / Ubuntu

Experimental Data

Packet captures and demonstration videos generated during the experiments are intentionally not stored in the main Git repository.

Large experimental artifacts can instead be distributed separately, for example through GitHub Releases.

Reports

The reports/ directory contains output generated during the security assessment, including experiments involving a single simulated drone and a three-drone environment.

Documentation

Additional project material is available under docs/:

\- attack\_plan.md — attack and experimentation plan

\- demo\_commands.txt — commands used during project demonstrations

\- presentation\_notes.txt — notes associated with the project presentation

Ethical Use

This repository contains cybersecurity research tooling developed for academic purposes.

The experiments were performed in a controlled and authorized PX4 SITL simulation environment. The tools are intended for security research, education, and testing of systems for which the user has explicit authorization.

Do not use these tools against UAVs, networks, ground stations, or other systems without authorization.

Limitations

The project focuses primarily on a simulated PX4/MAVLink environment. Results obtained in SITL should not automatically be assumed to apply identically to physical UAV systems, different autopilot implementations, different network configurations, or different MAVLink security configurations.

Disclaimer

This project is provided for educational and research purposes. Users are responsible for ensuring that any testing performed with the code complies with applicable laws, regulations, and authorization requirements.

