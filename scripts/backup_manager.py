#!/usr/bin/env python3
"""
Backup Manager for lm9dem
Handles background database backup operations
"""

import asyncio
import json
import logging
import os
import subprocess
import time
import uuid
from datetime import datetime
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BackupManager:
    def __init__(self):
        # Configuration from environment (NO DEFAULTS - FAIL FAST)
        self.downloads_dir = os.environ.get('DOWNLOADS_BASE_PATH')
        if not self.downloads_dir:
            raise RuntimeError("CRITICAL: DOWNLOADS_BASE_PATH environment variable is required")
            
        self.files_dir = f"{self.downloads_dir}/files"
        self.tokens_dir = f"{self.downloads_dir}/tokens" 
        self.jobs_dir = f"{self.downloads_dir}/jobs"
        
        # Ensure directories exist
        os.makedirs(self.files_dir, exist_ok=True)
        os.makedirs(self.tokens_dir, exist_ok=True)
        os.makedirs(self.jobs_dir, exist_ok=True)
        
        # Email configuration from environment (NO DEFAULTS)
        self.mailing_service_url = os.environ.get('MAILING_SERVICE_URL')
        self.mailing_token = os.environ.get('MAILING_TOKEN')
        self.admin_email = os.environ.get('ADMIN_EMAIL')
        self.downloads_domain = os.environ.get('DOWNLOADS_DOMAIN')
        
        # Cleanup scheduler status
        self.cleanup_scheduler_running = False
        self.last_cleanup_time = None
        
        # Validate required configuration
        if not self.mailing_service_url:
            raise RuntimeError("CRITICAL: MAILING_SERVICE_URL environment variable is required")
        if not self.mailing_token:
            raise RuntimeError("CRITICAL: MAILING_TOKEN environment variable is required")
        if not self.admin_email:
            raise RuntimeError("CRITICAL: ADMIN_EMAIL environment variable is required")
        if not self.downloads_domain:
            raise RuntimeError("CRITICAL: DOWNLOADS_DOMAIN environment variable is required")
    
    def load_backup_jobs(self) -> list:
        """Load backup jobs from filesystem"""
        try:
            jobs_file = f"{self.jobs_dir}/jobs.json"
            if os.path.exists(jobs_file):
                with open(jobs_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load backup jobs: {e}")
        return []
    
    def save_backup_jobs(self, jobs: list) -> bool:
        """Save backup jobs to filesystem"""
        try:
            jobs_file = f"{self.jobs_dir}/jobs.json"
            with open(jobs_file, 'w') as f:
                json.dump(jobs, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save backup jobs: {e}")
            return False
    
    def update_job_status(self, job_id: str, status: str, progress: str = "", error: str = ""):
        """Update job status in jobs file"""
        jobs = self.load_backup_jobs()
        
        for job in jobs:
            if job["id"] == job_id:
                job["status"] = status
                job["updated"] = datetime.now().isoformat()
                if progress:
                    job["progress"] = progress
                if error:
                    job["error"] = error
                break
        
        self.save_backup_jobs(jobs)
        logger.info(f"Job {job_id} updated: status={status}, progress={progress}")
    
    def generate_download_token(self) -> str:
        """Generate secure download token with expiration"""
        token_id = str(uuid.uuid4())
        expiry = int(time.time()) + (6 * 3600)  # 6 hours from now
        return f"{token_id}_{expiry}"
    
    def save_token_data(self, token: str, data: dict) -> bool:
        """Save token metadata to filesystem"""
        try:
            token_file = f"{self.tokens_dir}/{token}.json"
            with open(token_file, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save token data: {e}")
            return False
    
    async def send_email(self, to_email: str, subject: str, body: str) -> bool:
        """Send email notification via mailing service using curl (like ABG system)"""
        try:
            import subprocess
            import json
            
            # Create payload with admin email in CC for tracking
            payload = {
                "mail": {
                    "receiver": [to_email],
                    "cc": [self.admin_email],  # Always CC admin for backup tracking
                    "subject": subject,
                    "body": body
                },
                "smtp_server": "smtp-mail.outlook.com",
                "smtp_port": 587,
                "smtp_email": "notifications@experio.ma",
                "smtp_password": "not_used_for_oauth",
                "attachements": []
            }
            
            # Convert to JSON string
            payload_json = json.dumps(payload)
            
            # Use curl like ABG system
            curl_command = [
                "curl", "-s", "-X", "POST", self.mailing_service_url,
                "-H", "Content-Type: application/json",
                "-H", f"Authorization: Bearer {self.mailing_token}",
                "-d", payload_json
            ]
            
            # Execute curl command
            process = await asyncio.create_subprocess_exec(
                *curl_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                response_text = stdout.decode('utf-8')
                logger.info(f"Email curl response: {response_text}")
                
                # Check for success indicator (like ABG system)
                if "Done saving the email" in response_text:
                    logger.info(f"Email sent successfully to {to_email}")
                    return True
                else:
                    logger.warning(f"Email sent but unexpected response: {response_text}")
                    return True  # Still consider success if no error
            else:
                error_text = stderr.decode('utf-8')
                logger.error(f"Email failed: curl exit code {process.returncode} - {error_text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    async def execute_backup(self, job_id: str, database: str, user_email: str):
        """Execute the actual backup process"""
        try:
            self.update_job_status(job_id, "running", "Starting backup process...")
            
            # Generate timestamped filename
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            dump_filename = f"{database}_{timestamp}.dump"
            local_dump_path = f"{self.files_dir}/{dump_filename}"
            
            self.update_job_status(job_id, "running", "Executing remote backup script...")
            
            # Execute the backup script (adapted from v2-backup.sh logic)
            backup_script = "/app/scripts/backup_database.sh"
            
            if not os.path.exists(backup_script):
                # Create a simple backup script if it doesn't exist
                self.create_backup_script(backup_script)
            
            # Run backup with timeout
            process = await asyncio.create_subprocess_exec(
                backup_script, database, local_dump_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=1800)  # 30 min timeout
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise Exception("Backup timed out after 30 minutes")
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown backup error"
                stdout_msg = stdout.decode() if stdout else ""
                
                # Combine stdout and stderr for full error context
                full_error = f"Exit code: {process.returncode}"
                if stdout_msg.strip():
                    full_error += f"\nOutput: {stdout_msg.strip()}"
                if error_msg.strip() and error_msg != "Unknown backup error":
                    full_error += f"\nError: {error_msg.strip()}"
                
                raise Exception(f"Backup script failed: {full_error}")
            
            # Check if backup file was created and has reasonable size
            if not os.path.exists(local_dump_path):
                raise Exception("Backup file was not created")
            
            file_size = os.path.getsize(local_dump_path)
            if file_size == 0:
                raise Exception("Backup file is empty")
            
            if file_size > 2 * 1024 * 1024 * 1024:  # 2GB limit
                os.remove(local_dump_path)  # Clean up oversized file
                raise Exception("Backup file exceeds 2GB limit")
            
            self.update_job_status(job_id, "running", "Generating download link...")
            
            # Generate download token
            token = self.generate_download_token()
            
            # Save token metadata
            token_data = {
                "database": database,
                "filename": dump_filename,
                "file_path": local_dump_path,
                "user_email": user_email,
                "job_id": job_id,
                "created": datetime.now().isoformat(),
                "file_size": file_size
            }
            
            if not self.save_token_data(token, token_data):
                raise Exception("Failed to save download token")
            
            # Update job with completion
            jobs = self.load_backup_jobs()
            for job in jobs:
                if job["id"] == job_id:
                    job["status"] = "completed"
                    job["progress"] = f"Backup completed ({file_size // (1024*1024)}MB)"
                    job["download_token"] = token
                    job["updated"] = datetime.now().isoformat()
                    break
            
            self.save_backup_jobs(jobs)
            
            # Send success email - use public domain through Cloudflare → Firewall → Nginx ingress flow
            download_url = f"https://{self.downloads_domain}/downloads/{token}"
            subject = f"✅ Database Backup Ready - {database}"
            body = f"""
<h3>Database Backup Completed Successfully</h3>
<p><strong>Database:</strong> {database}</p>
<p><strong>File Size:</strong> {file_size // (1024*1024)} MB</p>
<p><strong>Download Link:</strong> <a href="{download_url}">{download_url}</a></p>
<br>
<p><em>Note: This download link will expire in 6 hours.</em></p>
<p><em>Backup completed at: {datetime.now().strftime("%d/%m/%y %H:%M:%S")}</em></p>
            """
            
            await self.send_email(user_email, subject, body)
            logger.info(f"Backup completed successfully: job={job_id}, database={database}, size={file_size//1024//1024}MB")
            
        except Exception as e:
            logger.error(f"Backup failed: job={job_id}, database={database}, error={str(e)}")
            
            # Update job with failure
            self.update_job_status(job_id, "failed", f"Backup failed: {str(e)}", str(e))
            
            # Send failure email to admin
            subject = f"❌ Database Backup Failed - {database}"
            body = f"""
<h3>Database Backup Failed</h3>
<p><strong>Database:</strong> {database}</p>
<p><strong>User Email:</strong> {user_email}</p>
<p><strong>Job ID:</strong> {job_id}</p>
<p><strong>Error:</strong> {str(e)}</p>
<br>
<p><em>Failed at: {datetime.now().strftime("%d/%m/%y %H:%M:%S")}</em></p>
            """
            
            await self.send_email(self.admin_email, subject, body)
            
            # Clean up partial files
            if os.path.exists(local_dump_path):
                try:
                    os.remove(local_dump_path)
                except:
                    pass
    
    def create_backup_script(self, script_path: str):
        """Create the backup script if it doesn't exist (should not be needed with proper deployment)"""
        # This should not be called in production since the script should be copied via Dockerfile
        logger.warning("Backup script not found at expected location, creating placeholder")
        
        script_content = '''#!/bin/bash
echo "ERROR: Real backup script not found!"
echo "Please ensure backup_database.sh is properly deployed in the container"
exit 1
'''
        
        os.makedirs(os.path.dirname(script_path), exist_ok=True)
        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o755)
    
    async def cleanup_expired_files(self):
        """Clean up expired files, tokens, and old job entries"""
        try:
            current_time = time.time()
            self.last_cleanup_time = datetime.now()
            cleaned_files = 0
            cleaned_jobs = 0
            
            # Clean up expired token files
            for token_file in os.listdir(self.tokens_dir):
                if token_file.endswith('.json'):
                    token = token_file[:-5]  # Remove .json extension
                    try:
                        token_id, expiry_str = token.split('_')
                        expiry = int(expiry_str)
                        
                        if current_time > expiry:
                            # First, try to remove associated backup file before removing token
                            try:
                                with open(f"{self.tokens_dir}/{token_file}", 'r') as f:
                                    token_data = json.load(f)
                                    file_path = token_data.get("file_path", "")
                                    if file_path and os.path.exists(file_path):
                                        os.remove(file_path)
                                        logger.info(f"Removed expired backup file: {file_path}")
                            except Exception as e:
                                logger.warning(f"Could not remove backup file for token {token}: {e}")
                            
                            # Then remove token file
                            os.remove(f"{self.tokens_dir}/{token_file}")
                            
                            cleaned_files += 1
                            logger.info(f"Cleaned up expired token: {token}")
                    except (ValueError, IndexError):
                        continue
            
            # Clean up old job entries (remove jobs older than 6 hours)
            cleaned_jobs = self.cleanup_old_jobs(current_time)
            
            total_cleaned = cleaned_files + cleaned_jobs
            if total_cleaned > 0:
                logger.info(f"Cleanup completed: removed {cleaned_files} expired files and {cleaned_jobs} old job entries")
            else:
                logger.debug("Cleanup completed: no expired files or old jobs found")
        
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            
    def cleanup_old_jobs(self, current_time: float) -> int:
        """Clean up old job entries from jobs.json (older than 6 hours)"""
        try:
            jobs = self.load_backup_jobs()
            if not jobs:
                return 0
                
            original_count = len(jobs)
            six_hours_ago = current_time - (6 * 3600)  # 6 hours in seconds
            
            # Filter out jobs older than 6 hours
            # Check both main download_token and shared_with tokens
            active_jobs = []
            for job in jobs:
                job_expired = True
                
                # Check main download token
                main_token = job.get("download_token", "")
                if main_token and "_" in main_token:
                    try:
                        _, expiry_str = main_token.split('_')
                        main_expiry = int(expiry_str)
                        if main_expiry > current_time:
                            job_expired = False
                    except (ValueError, IndexError):
                        pass
                
                # Check shared tokens if main token is expired
                if job_expired:
                    shared_with = job.get("shared_with", [])
                    for share in shared_with:
                        share_token = share.get("token", "")
                        if share_token and "_" in share_token:
                            try:
                                _, expiry_str = share_token.split('_')
                                share_expiry = int(expiry_str)
                                if share_expiry > current_time:
                                    job_expired = False
                                    break
                            except (ValueError, IndexError):
                                continue
                
                # Keep job if any of its tokens are still valid
                if not job_expired:
                    active_jobs.append(job)
                else:
                    logger.info(f"Removing expired job: {job['id']} (database: {job.get('database', 'unknown')})")
            
            # Save updated jobs list
            if len(active_jobs) < original_count:
                self.save_backup_jobs(active_jobs)
                cleaned_count = original_count - len(active_jobs)
                logger.info(f"Job cleanup: removed {cleaned_count} old job entries")
                return cleaned_count
            
            return 0
        except Exception as e:
            logger.error(f"Job cleanup failed: {e}")
            return 0
            
    def get_cleanup_status(self):
        """Get cleanup scheduler status"""
        return {
            "scheduler_running": self.cleanup_scheduler_running,
            "last_cleanup_time": self.last_cleanup_time.isoformat() if self.last_cleanup_time else None,
            "next_cleanup_in_minutes": 60 if self.cleanup_scheduler_running else None
        }

    async def start_cleanup_scheduler(self):
        """Start periodic cleanup of expired files"""
        try:
            self.cleanup_scheduler_running = True
            logger.info("Starting cleanup scheduler - runs every hour")
            
            while True:
                try:
                    await asyncio.sleep(3600)  # Run every hour
                    await self.cleanup_expired_files()
                except Exception as e:
                    logger.error(f"Cleanup scheduler error: {e}")
                    await asyncio.sleep(300)  # Wait 5 minutes on error
        except Exception as e:
            logger.error(f"Cleanup scheduler failed to start: {e}")
            self.cleanup_scheduler_running = False
        finally:
            logger.warning("Cleanup scheduler has stopped")
            self.cleanup_scheduler_running = False

# Global backup manager instance
backup_manager = BackupManager()