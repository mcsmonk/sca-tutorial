# sca-tutorial


Structure

```
├──── README.md
|
├──── python-DPA-AES
|
|
|
├──── ...
|       ├── ...
|           ├── ...
|           ├── ...
|
```

# Datasets

## public dataset

### 1. DPAconstest  \[[link](<http://www.dpacontest.org/home/>)\]

1.1  DPAcontest V2 \[[link](<http://www.dpacontest.org/v2/index.php>)\]

- organized by the [VLSI](http://www.comelec.enst.fr/recherche/sen.en) research group from the [COMELEC](http://www.comelec.enst.fr/accueil.en) department of the [Télécom ParisTech](http://www.telecom-paristech.fr/en/) french University
- the SASEBO GII board used for the acquisitions
- AES-128 Hardware implementation without countermeasure

1.2 DPAcontest V4 \[[link](<http://www.dpacontest.org/v4/index.php>)\]

- organized by the [Digital Electronic Systems](http://www.comelec.enst.fr/recherche/sen.en)research group from the [Communication & Electronics](http://www.comelec.enst.fr/accueil.en) department of the [Télécom ParisTech](http://www.telecom-paristech.fr/eng/) french University
- Several protected implementations of AES are targeted
  - a masked implementation of AES-256 on an Atmel ATMega-163 smart-card (AES-256 RSM)
  - an improved masked implementation of AES-128 on an Atmel ATMega-163 smart-card (v4.2)

### 2. ASCAD  \[[link](<https://github.com/ANSSI-FR/ASCAD>), [paper](<https://eprint.iacr.org/2018/053.pdf>)\]

- ANSSI has provided source code implementations of two **masked AES** on the ATMega8515 MCU target
  - \[[ANSSI-FR/secAES-ATmega8515](https://github.com/ANSSI-FR/secAES-ATmega8515)\]
- the first version (v1) of the masked AES
- EM (ElectroMagnetic) measurements
  - 60,000 traces
  - 100,000 time samples
  - sampling rate 2 GS/s 
- The traces are synchronized, and no specific hardware countermeasure has been activated on the ATMega8515

### 3. Grizzly \[[link](<https://www.cl.cam.ac.uk/research/security/datasets/grizzly/>)\]

- by Omar Choudary in August 2013
- power-analysis traces for an 8-bit load instruction
- recordings of the power-supply current of the 8-bit CPU Atmel XMEGA 256 A3U, an easily available microcontroller without side-channel countermeasures
