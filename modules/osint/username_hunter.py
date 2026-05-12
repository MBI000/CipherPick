import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

class UsernameHunter:
    def __init__(self, username):
        self.username = username
        
        # Merged list of 22 popular sites requested by the user with Sherlock's logic
        self.sites = {
            "Facebook": {
                "urlMain": "https://www.facebook.com/{}",
                "urlProbe": "https://www.facebook.com/{}/videos/",
                "errorType": "message",
                "errorMsg": "This page isn't available"
            },
            "Instagram": {
                "urlMain": "https://www.instagram.com/{}/",
                "urlProbe": "https://www.instagram.com/{}/",
                "errorType": "message",
                "errorMsg": "Sorry, this page isn't available."
            },
            "X (Twitter)": {
                "urlMain": "https://twitter.com/{}",
                "urlProbe": "https://twitter.com/{}",
                "errorType": "status_code"
            },
            "YouTube": {
                "urlMain": "https://www.youtube.com/@{}",
                "urlProbe": "https://www.youtube.com/@{}",
                "errorType": "status_code"
            },
            "TikTok": {
                "urlMain": "https://www.tiktok.com/@{}",
                "urlProbe": "https://www.tiktok.com/@{}",
                "errorType": "status_code"
            },
            "Pinterest": {
                "urlMain": "https://www.pinterest.com/{}/",
                "urlProbe": "https://www.pinterest.com/oembed.json?url=https://www.pinterest.com/{}/",
                "errorType": "status_code"
            },
            "Twitch": {
                "urlMain": "https://www.twitch.tv/{}",
                "urlProbe": "https://www.twitch.tv/{}",
                "errorType": "message",
                "errorMsg": "world&#39;s leading video platform"
            },
            "Snapchat": {
                "urlMain": "https://www.snapchat.com/add/{}",
                "urlProbe": "https://www.snapchat.com/add/{}",
                "errorType": "status_code"
            },
            "LinkedIn": {
                "urlMain": "https://www.linkedin.com/in/{}/",
                "urlProbe": "https://www.linkedin.com/in/{}/",
                "errorType": "status_code"
            },
            "Medium": {
                "urlMain": "https://medium.com/@{}",
                "urlProbe": "https://medium.com/feed/@{}",
                "errorType": "message",
                "errorMsg": "<body"
            },
            "GitHub": {
                "urlMain": "https://github.com/{}",
                "urlProbe": "https://github.com/{}",
                "errorType": "status_code"
            },
            "Reddit": {
                "urlMain": "https://www.reddit.com/user/{}",
                "urlProbe": "https://www.reddit.com/user/{}",
                "errorType": "message",
                "errorMsg": "nobody on Reddit goes by that name"
            },
            "HackerNews": {
                "urlMain": "https://news.ycombinator.com/user?id={}",
                "urlProbe": "https://news.ycombinator.com/user?id={}",
                "errorType": "message",
                "errorMsg": "No such user."
            },
            "Vimeo": {
                "urlMain": "https://vimeo.com/{}",
                "urlProbe": "https://vimeo.com/{}",
                "errorType": "status_code"
            },
            "GitLab": {
                "urlMain": "https://gitlab.com/{}",
                "urlProbe": "https://gitlab.com/api/v4/users?username={}",
                "errorType": "message",
                "errorMsg": "[]"
            },
            "Flickr": {
                "urlMain": "https://www.flickr.com/people/{}/",
                "urlProbe": "https://www.flickr.com/people/{}/",
                "errorType": "status_code"
            },
            "Dev.to": {
                "urlMain": "https://dev.to/{}",
                "urlProbe": "https://dev.to/{}",
                "errorType": "status_code"
            },
            "Patreon": {
                "urlMain": "https://www.patreon.com/{}",
                "urlProbe": "https://www.patreon.com/{}",
                "errorType": "status_code"
            },
            "Spotify": {
                "urlMain": "https://open.spotify.com/user/{}",
                "urlProbe": "https://open.spotify.com/user/{}",
                "errorType": "status_code"
            },
            "Pastebin": {
                "urlMain": "https://pastebin.com/u/{}",
                "urlProbe": "https://pastebin.com/u/{}",
                "errorType": "message",
                "errorMsg": "Not Found (#404)"
            },
            "Roblox": {
                "urlMain": "https://www.roblox.com/user.aspx?username={}",
                "urlProbe": "https://www.roblox.com/user.aspx?username={}",
                "errorType": "status_code"
            },
            "Wikipedia": {
                "urlMain": "https://en.wikipedia.org/wiki/User:{}",
                "urlProbe": "https://en.wikipedia.org/wiki/User:{}",
                "errorType": "message",
                "errorMsg": "Wikipedia does not have a user page with this exact name."
            }
        }

    def _check_site(self, site_name, site_data):
        # Sherlock uses urlProbe to do the actual background checking
        probe_url = site_data["urlProbe"].format(self.username)
        main_url = site_data["urlMain"].format(self.username)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        }
        
        req = urllib.request.Request(probe_url, headers=headers)
        error_type = site_data.get("errorType")
        
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            response = urllib.request.urlopen(req, timeout=10, context=ctx)
            html = response.read().decode('utf-8', errors='ignore')
            status_code = response.getcode()

            # Message-based validation
            if error_type == "message":
                error_msg = site_data.get("errorMsg")
                if error_msg and error_msg in html:
                    return site_name, main_url, "Not Found"
                return site_name, main_url, "Found"

            # Status Code validation
            elif error_type == "status_code":
                if status_code >= 200 and status_code < 300:
                    return site_name, main_url, "Found"
                else:
                    return site_name, main_url, "Not Found"

        except urllib.error.HTTPError as e:
            # If the site throws a 404, the user doesn't exist.
            if e.code == 404:
                return site_name, main_url, "Not Found"
            
            # If it's a 200 OK but we hit an HTTPError, we can fallback to checking the error page HTML
            if error_type == "message":
                try:
                    error_html = e.read().decode('utf-8', errors='ignore')
                    if site_data.get("errorMsg") and site_data.get("errorMsg") in error_html:
                        return site_name, main_url, "Not Found"
                    # If the error message ISN'T on the error page, we assume the user exists but is private
                    return site_name, main_url, "Found"
                except:
                    pass
                    
            return site_name, main_url, f"Blocked (HTTP {e.code})"
            
        except Exception as e:
            return site_name, main_url, f"Error ({type(e).__name__})"

    def hunt(self):
        print(f"\n[*] Launching Engine for: \033[92m{self.username}\033[0m\n")
        
        found = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self._check_site, name, data) for name, data in self.sites.items()]
            
            for future in futures:
                site_name, main_url, status = future.result()
                if status == "Found":
                    # Only the '+' is colored green
                    print(f"[\033[92m+\033[0m] {site_name}: {main_url}")
                    found.append(main_url)
                elif "Blocked" in status:
                    print(f"[\033[93m!\033[0m] {site_name}: {status}") 
                else:
                    # Only the '-' is colored red
                    print(f"[\033[91m-\033[0m] {site_name}: {status}")
                    
        print(f"\n[*] Hunt completed! Found \033[92m{len(found)}\033[0m profiles for '{self.username}'.")
        return found
