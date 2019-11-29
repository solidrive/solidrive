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

### Multi-platform framework evaluation
* Requirements
  1. iOS and Android
  2. background services
  3. Rust code in background service
* Optional
  4. Share UI code for all platforms

#### Compare UI design and devlepment for Flutter/Dart and Kotlin/Multiplatform
In a Kotlin-Multiplatform project, do you need to write the UI separately for each platform?
* According to [this blog](https://goobar.io/2019/06/13/kotlin-vs-flutter-are-you-comparing-them-fairly/) the answer is yes.

Because we want as much code shared as possible, we'd opt for Flutter.

#### React Native

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