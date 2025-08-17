## Version 1.2.0 – 17.08.2025

### New Features

- Implemented cross-platform crash dump analysis (internal analyzer)
- Added detailed dump information: process name, exception code, and system information
- Introduced ability to delete previously uploaded dump files
- Added SQLite database for ticket persistence
- Integrated Waitress server for production releases (more stable web delivery)
- Enhanced CSRF protection and improved accessibility

### Refactoring & Maintenance

- Moved dump analysis into a separate module (better structure and maintainability)
- Limited upload size to prevent connection resets
- Bumped version to 1.2.0 and updated changelog

## Version 1.1.0 - 27.10.2024

- Feature: New settings icon
- Feature: Dark mode
- Feature: New Exception Codes
- Feature: Implement the new logo

## Version 1.0.5 - 02.09.2024

- Security Fix: URL redirection from remote source

## Version 1.0.4 - 01.10.2024

- Security Fix: to the file path handling in the view_analysis function in app.py.
  It ensures that the file path is normalized and checked to prevent directory traversal attacks.
- Security Fix: Added URL validation to prevent open redirect vulnerabilities.
  - Imported `urlparse` from `urllib.parse`.
  - Replaced the direct use of `request.url` with a validated version.
  - Ensured that the URL does not contain an explicit host name and is a relative path.

## Version 1.0.3 - 30.09.2024

- New language: Dutch can now be used as a language
- Bug fixes: requirements.txt updated

## Version 1.0.2 - 28.09.2024

- New language: English can now be used as a language
- Bugfixes

## Version 1.0.1 - 28.09.2024

- Bugfix if a capitalized .DMP file was uploaded, it was displayed as invalid. This has been fixed
- Changelogs are now in English

## Version 1.0.0 - 25.09.2024

- First version of the application
- Implementation of the dump analysis
- Addition of drag-and-drop functionality for file uploads
- Display of upload date and time for each ticket

## Version 0.9.0 - 20.09.2024

- Development of the basic functions
- Setting up the Flask application
- Implementation of file upload and analysis
