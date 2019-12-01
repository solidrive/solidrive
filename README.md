# Coegi - Decentralized file synchronization and sharing
Coegi aims to deliver a decentralized alternative to centralized file synchronization and sharing platforms, such as the proprietary Dropbox and Google Drive, as well as the open-source Nextcloud or ownCloud.
The decentralization aspect is achieved by making use of the specifications and components which are developed by the [SOLID project][solid].

## General questions
* Does it make sense to use HTTP3/QUIC for transport?

## Shared Libraries
A goal with regard to implementation is to share the implementation of authentication and data transfer among all clients.
The approach is to build all this functionality in one or several Rust libraries, and find a way to link it in the mobile and desktop applications.

Libraries (produced and) used:

* [libsolid-rs](libsolid-rs)

## Coegi Mobile (Android/iOS)
* Mobile Application for Android/iOS

### Prerequisites
* Choose a multi-platform framework which supports calling Rust in the background service

### v0.1
* Multi-platform App with background service which links to Rust library

### v0.2
* Login/Authentication
* List
* View (download to memory)

### v0.3
* Download to filesystem

### v0.4
* Upload files
* Delete files

### v0.5
* Un/Share files with permissions

### v0.6
* File synchronization Upload only mode

### v0.7
* File synchronization Download

### v1.0
* Publish on F-Droid
* Party with non-alcoholic beer \o/

## Coegi CLI (Linux/Windows/Mac)
* TODO

## Coegi Website
* TODO

## Coegi Daemon (Linux/Windows/Mac)
* TODO

[solid]: https://solid.mit.edu