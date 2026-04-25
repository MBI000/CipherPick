import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

class UsernameHunter:
    def __init__(self, username):
        self.username = username
        
        # A curated list of popular sites, similar to Sherlock's data.json
        self.sites = {
            "Facebook": "https://www.facebook.com/{}",
            "Instagram": "https://www.instagram.com/{}/",
            "X (Twitter)": "https://twitter.com/{}",
            "YouTube": "https://www.youtube.com/@{}",
            "TikTok": "https://www.tiktok.com/@{}",
            "Pinterest": "https://www.pinterest.com/{}/",
            "Twitch": "https://www.twitch.tv/{}",
            "Snapchat": "https://www.snapchat.com/add/{}",
            "LinkedIn": "https://www.linkedin.com/in/{}/",
            "Medium": "https://medium.com/@{}",
            "GitHub": "https://github.com/{}",
            "Reddit": "https://www.reddit.com/user/{}",
            "HackerNews": "https://news.ycombinator.com/user?id={}",
            "Vimeo": "https://vimeo.com/{}",
            "GitLab": "https://gitlab.com/{}",
            "Flickr": "https://www.flickr.com/people/{}/",
            "Dev.to": "https://dev.to/{}",
            "Patreon": "https://www.patreon.com/{}",
            "Spotify": "https://open.spotify.com/user/{}",
            "Pastebin": "https://pastebin.com/u/{}",
            "Roblox": "https://www.roblox.com/user.aspx?username={}",
            "Wikipedia": "https://en.wikipedia.org/wiki/User:{}"
        }

    def _check_site(self, site_name, url_template):
        url = url_template.format(self.username)
        # We spoof a generic User-Agent so sites don't immediately block urllib
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        
        # Common phrases found on "Soft 404" pages when a user doesn't exist
        error_phrases = [
            b"page not found", b"couldn't find", b"does not exist",
            b"user not found", b"account suspended", b"not be found",
            b"404 not found", b"content unavailable", b"this page isn't available",
            b"nobody goes by that name"
        ]
        
        try:
            response = urllib.request.urlopen(req, timeout=5)
            
            # Check for redirect to a login/home page (soft 404 via redirect)
            # Example: asking for /nonexistentuser redirects to /login
            final_url = response.geturl()
            if final_url != url and ("login" in final_url or final_url.strip('/') == url_template.split('/{')[0].strip('/')):
                return site_name, url, False
                
            if response.getcode() == 200:
                # Read a chunk of the response to check for soft 404 text
                html = response.read(15000).lower()
                for phrase in error_phrases:
                    if phrase in html:
                        return site_name, url, False
                return site_name, url, True
                
        except urllib.error.HTTPError:
            # 404 generally means the user does not exist
            pass 
        except Exception:
            # Network drops, timeouts, DNS errors
            pass 
            
        return site_name, url, False

    def hunt(self):
        print(f"\n[*] Hunting for username: \033[92m{self.username}\033[0m across {len(self.sites)} platforms...")
        found = []
        
        # Use threading to quickly dispatch all requests at once
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self._check_site, name, url) for name, url in self.sites.items()]
            
            for future in futures:
                site_name, url, exists = future.result()
                if exists:
                    print(f"[\033[92m+\033[0m] {site_name}: {url}")
                    found.append(url)
                else:
                    print(f"[\033[91m-\033[0m] {site_name}: Not Found")
                    
        print(f"\n[*] Hunt completed! Found \033[92m{len(found)}\033[0m profiles for '{self.username}'.")
        return found
