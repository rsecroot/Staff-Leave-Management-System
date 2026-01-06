
**BUG Author: [Ravi Sharma]**

**Product Information:**

- Vendor Homepage: (https://phpgurukul.com/staff-leave-management-system-using-django-python-sqlite/)
- Affected Version: [<= v1.0]
- BUG Author: Ravi Sharma

**Vulnerability Details**

- Type: Stored Cross-Site Scripting (XSS) via Unrestricted SVG File Upload in Staff Leave Management System
- Affected URL: http://127.0.0.1:8000/Profile, http://127.0.0.1:8000/Admin/Staff/Add
- Vulnerable Parameter:  /staffleave/slms/slms/adminviews.py - Profile Pic

**Vulnerable Files:**

- File Name: /staffleave/
- Path: /staffleave/slms/slms/adminviews.py 

**Vulnerability Type**

- Stored Cross-Site Scripting CWE: CWE-79, CWE-434, CWE-80
- Severity Level: 8.7 (HIGH)

**Root Cause:**

The Django application's adminviews.py file contains two vulnerable functions:

1. **ADD_STAFF function (Lines 18-47):**
```python
profile_pic = request.FILES.get('profile_pic')
# No validation performed
user = CustomUser(first_name=first_name, last_name=last_name, 
                  profile_pic=profile_pic, # Directly saved without validation
                  username=username)
```

2. **UPDATE_STAFF function (Lines 66-94):**
```python
profile_pic = request.FILES.get('profile_pic')
# No validation performed
if profile_pic != None and profile_pic != "":
    user.profile_pic = profile_pic  # Directly saved without validation
```

**Security Failures:**

- No file extension validation (accepts .svg, .html, .js, any extension)
- No MIME type verification
- No content sanitization or inspection
- No use of Django's FileExtensionValidator
- No verification that uploaded file is actually an image
- Files served with original MIME type (image/svg+xml), allowing script execution

1. **Affected Code:**

Line 22 (ADD_STAFF): _profile_pic = request.FILES.get('profile_pic')_

Line 37:_user = CustomUser(profile_pic = profile_pic)  # No validation_

Line 67 (UPDATE_STAFF):_profile_pic = request.FILES.get('profile_pic')_

Line 87:_user.profile_pic = profile_pic  # No validation_

**Impact:**

Django application accepts file uploads without validation. Missing FileExtensionValidator and content verification. Allows SVG files with embedded JavaScript to be stored and rendered.

**Vulnerability Details:**
-------------------------------------------------------------------------------------------------------------------------------------

**Description:**

A critical stored cross-site scripting (XSS) vulnerability exists in the Staff Leave Management System due to unrestricted file upload functionality in the profile picture feature. The application fails to validate uploaded file types and content, allowing authenticated administrators to upload malicious SVG files containing embedded JavaScript code.

The vulnerability exists in two locations:
1. Admin profile update functionality (http://127.0.0.1:8000/Profile)
2. Staff creation functionality (http://127.0.0.1:8000/Admin/Staff/Add)

The application accepts SVG files without content inspection or sanitization. When these files are rendered in the browser (either by viewing user profiles or opening images in new tabs), the embedded JavaScript executes in the security context of any user viewing the content, including other administrators.

**Vulnerable Code Example:**

/staffleave/slms/slms/adminviews.py

<img width="468" height="56" alt="Screenshot 2026-01-06 at 20 33 31" src="https://github.com/user-attachments/assets/a41de11b-2534-42ce-a7d4-02aaacd4a99b" />

<img width="1234" height="141" alt="Screenshot 2026-01-06 at 20 35 07" src="https://github.com/user-attachments/assets/7993b135-2e05-436e-be9a-5487d7b35663" />

<img width="526" height="53" alt="Screenshot 2026-01-06 at 20 36 00" src="https://github.com/user-attachments/assets/44edfdc0-84c0-4c82-9230-2584770353c2" />

**Step-by-Step Reproduction:**
### **Trigger XSS as Admin**

**First Scenario:**
1. Login as Admin
2. Navigate to: http://127.0.0.1:8000/Profile, http://127.0.0.1:8000/Admin/Staff/Add
3. Click "Browse..." under "Upload Profile Pic"
4. Select: malicious.svg
5. Click "Update"
6. File uploaded to: /malicious.svg and triggerd as XSS attack.

**Second Scenario:**
1. Login as Admin
2. Navigate to: http://127.0.0.1:8000/Admin/Staff/Add
3. Click "Browse..." under "Upload Profile Pic"
4. Select: malicious.svg
5. Click "ADD STAFF"
6. File uploaded to: /malicious.svg and triggerd as XSS attack.

**Screenshots**
[Attach screenshots showing:]

<img width="973" height="855" alt="Screenshot 2026-01-06 at 18 33 51" src="https://github.com/user-attachments/assets/cc18b89f-1c4b-4038-92b9-665030b1bcc3" />


<img width="959" height="1021" alt="Screenshot 2026-01-06 at 20 27 09" src="https://github.com/user-attachments/assets/4bcce4ee-b894-49b5-b120-8964499204e6" />

<img width="1812" height="1027" alt="Screenshot 2026-01-06 at 19 44 11" src="https://github.com/user-attachments/assets/82a11d6d-92f3-4b2e-a31b-75a3858d2575" />

<img width="1268" height="921" alt="Screenshot 2026-01-06 at 18 33 35" src="https://github.com/user-attachments/assets/c46ad687-ad28-4b5a-824c-aa4af957370b" />

### **Trigger XSS as STAFF Member**

1. Login as STAFF User
2. Right Click Profile Picture and Open image in new tab
3. Page loads malicious SVG in <img> tag
4. XSS executes: Alert shows XSS attack

**Screenshots**
[Attach screenshots showing:]

<img width="693" height="590" alt="Screenshot 2026-01-06 at 19 45 16" src="https://github.com/user-attachments/assets/797c9a00-98fb-4607-8e1c-0f4a217f5910" />

<img width="1347" height="871" alt="Screenshot 2026-01-06 at 20 29 36" src="https://github.com/user-attachments/assets/cd5d0c32-01d0-4d11-b673-e93bcc915ac2" />

**Impact Assessment:**

The XSS executes with administrator privileges, allowing an attacker to:
- Admin can upload malicious SVG
- XSS executes when viewing staff list/profile
- Session hijacking possible
- Admin account compromise

**Affected Components:**

- Profile Update Functionality
- Staff Creation Functionality
- File Storage and Serving
- File Rendering - Admin/Staff Page (XSS TRIGGER POINT)

**Remediation Recommendations:**

**Immediate Fix**

1. Disallow Dangerous File Types
- Block uploads of executable formats such as:.svg, .html, .htm, .xml
- Use a strict allowlist (e.g., .jpg, .png, .pdf).

2. Enforce Proper Content-Type Handling
- Validate file content using server-side MIME type checks.
- Do not rely solely on client-provided Content-Type headers.

3. Sanitize SVG Files (If SVG Is Required)
- Remove <script>, event handlers (onload, onclick), and external references.
- Use a trusted SVG sanitization library.

4. Serve Uploaded Files Safely
- Serve uploads from a separate domain (e.g., uploads.example-cdn.com).
- Apply the following HTTP headers:
Content-Disposition: attachment
Content-Type: application/octet-stream
X-Content-Type-Options: nosniff

5. Implement Content Security Policy (CSP)
- Use a restrictive CSP to limit script execution: Content-Security-Policy: default-src 'none'; img-src 'self'

6. Disable Inline JavaScript Execution
- Avoid rendering user-uploaded content directly within application pages.

7. Conduct security code review

# Secure Code Example:

#models.py (CustomUser model):
from django.core.validators import FileExtensionValidator

class CustomUser(AbstractUser):
    profile_pic = models.ImageField(
        upload_to='profile_pics/',
        validators=[FileExtensionValidator(['jpg', 'jpeg', 'png', 'gif'])],
        blank=True,
        null=True
    )

**#Secure File Serving:**

#urls.py - Create secure image serving view:
from django.http import FileResponse
from django.contrib.auth.decorators import login_required
import os

@login_required
def serve_profile_pic(request, filename):
    # Validate filename
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(settings.MEDIA_ROOT, 'profile_pics', safe_filename)
    
    if not os.path.exists(filepath):
        return HttpResponse('File not found', status=404)
    
    # Validate MIME type
    import mimetypes
    mime_type, _ = mimetypes.guess_type(filepath)
    allowed_mimes = ['image/jpeg', 'image/png', 'image/gif']
    
    if mime_type not in allowed_mimes:
        return HttpResponse('Invalid file type', status=403)
    
    # Serve with correct Content-Type
    response = FileResponse(open(filepath, 'rb'))
    response['Content-Type'] = mime_type
    response['X-Content-Type-Options'] = 'nosniff'
    return response

**References**

- OWASP Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- CWE-80: https://cwe.mitre.org/data/definitions/80.html
