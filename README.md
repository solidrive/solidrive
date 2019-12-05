# SoLiDrive - Decentralized file synchronization and sharing
SoLiDrive aims to deliver a decentralized alternative to centralized file synchronization and sharing platforms, such as the proprietary Dropbox and Google Drive, as well as the open-source Nextcloud or ownCloud.
The decentralization aspect is achieved by making use of the specifications and components which are developed by the [SOLID project][solid].

## What is Solid?
Solid, which stands for **So**cial **Li**nked **D**ata, is a set of specifications and tools that provides separation between web applications and the data they consume. It allows end-users to have ownership over their data by providing them with the ability to choose where this data is stored and who can access it. 

## General questions
* Does it make sense to use HTTP3/QUIC for transport?

## Shared Libraries
A goal with regard to implementation is to share the implementation of authentication and data transfer among all clients.
The approach is to build all this functionality in one or several Rust libraries, and find a way to link it in the mobile and desktop applications.

Libraries (produced and) used:

* [libsolid-rs](libsolid-rs)

## SoLiDrive Mobile (Android/iOS)
* [SoLiDrive Android Client][solidrive-android-client]

## SoLiDrive CLI (Linux/Windows/Mac)
* TODO

## SoLiDrive Website
* TODO

## SoLiDrive Daemon (Linux/Windows/Mac)
* TODO

[solid]: https://solid.mit.edu
[solidrive-android-client]: https://github.com/solidrive/solidrive-android-client