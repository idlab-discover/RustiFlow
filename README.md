# Real-Time Adaptive Feature Extraction for ML-Based Network Intrusion Detection
This is a feature extraction tool build in Rust using eBPF for network intrusion detection


### Supported datasets

- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) from the Canadian Institute for Cybersecurity
- [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) from the Canadian Institute for Cybersecurity
- [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html) from the Canadian Institute for Cybersecurity
- [CIC-IDS-Collection](https://www.kaggle.com/datasets/dhoogla/cicidscollection) from Laurens D'Hooge
- [CTU-13](https://www.stratosphereips.org/datasets-ctu13) from the CTU university of the Czech Republic
- [CTU-13](https://www.kaggle.com/datasets/dhoogla/ctu13) from Laurens D'Hooge
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) from UNSW Sydney
- [UNSW-NB15](https://www.kaggle.com/datasets/dhoogla/unswnb15) from Laurens D'Hooge

The datasets from Laurens D'Hooge are cleaned up versions from the original ones. He removed the contaminant features. You can read about his work on his [kaggle account](https://www.kaggle.com/dhoogla) or in his [paper](https://ieeexplore.ieee.org/abstract/document/9851974).

### Supported file extensions

- CSV
- pcap
- parquet