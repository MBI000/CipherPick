import matplotlib.pyplot as plt
import matplotlib.patches as patches

def main():
    # Set up a 1x2 grid for subplots (2 diagrams in 1 plot window)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))
    
    # ==========================================
    # PLOT 1: Ports (Left Side)
    # ==========================================
    universal_ports = set(range(1, 65536))
    common_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443}
    
    # Draw Universal Set
    circle1_u = patches.Circle((0.5, 0.5), 0.45, fill=True, color='lightblue', alpha=0.6)
    ax1.add_patch(circle1_u)
    
    # Draw Subset
    circle1_c = patches.Circle((0.5, 0.35), 0.2, fill=True, color='salmon', alpha=0.9)
    ax1.add_patch(circle1_c)
    
    ax1.text(0.5, 0.75, f'Universal Set (U)\nAll Ports: 1-65535\nSize: {len(universal_ports)}', 
             ha='center', va='center', fontsize=12, fontweight='bold', color='midnightblue')
    ax1.text(0.5, 0.35, f'Subset (C)\nCommon Ports\nSize: {len(common_ports)}\n{{21, 22, 80, 443...}}', 
             ha='center', va='center', fontsize=10, fontweight='bold', color='darkred')
             
    ax1.set_xlim(0, 1)
    ax1.set_ylim(0, 1)
    ax1.axis('off')
    ax1.set_title('Network Ports', fontsize=16, fontweight='bold')

    # ==========================================
    # PLOT 2: Social Media (Right Side)
    # ==========================================
    universal_size = 4000
    hunter_subset = {
        "Facebook", "Instagram", "X (Twitter)", "YouTube", "TikTok", "Pinterest", "Twitch", 
        "Snapchat", "LinkedIn", "Medium", "GitHub", "Reddit", "HackerNews", 
        "Vimeo", "GitLab", "Flickr", "Dev.to", "Patreon", "Spotify", "Pastebin", 
        "Roblox", "Wikipedia"
    }
    
    # Draw Universal Set
    circle2_u = patches.Circle((0.5, 0.5), 0.45, fill=True, color='lightgreen', alpha=0.5)
    ax2.add_patch(circle2_u)
    
    # Draw Subset
    circle2_c = patches.Circle((0.5, 0.35), 0.25, fill=True, color='seagreen', alpha=0.9)
    ax2.add_patch(circle2_c)
    
    ax2.text(0.5, 0.8, f'Universal Set (U)\nAll Social Platforms\nSize: ~{universal_size}', 
             ha='center', va='center', fontsize=12, fontweight='bold', color='darkgreen')
             
    subset_text = "Subset (C) - 22 Most Used\n\nFacebook, Instagram, X,\nYouTube, TikTok, Reddit,\nGitHub, LinkedIn, Twitch..."
    ax2.text(0.5, 0.35, subset_text, 
             ha='center', va='center', fontsize=10, fontweight='bold', color='white')
             
    ax2.set_xlim(0, 1)
    ax2.set_ylim(0, 1)
    ax2.axis('off')
    ax2.set_title('Social Media Targets', fontsize=16, fontweight='bold')

    # ==========================================
    # Finalize and Show
    # ==========================================
    plt.suptitle('CipherPick Universal Sets & Subsets', fontsize=20, fontweight='bold', y=0.95)
    
    # Save the output image and display the plot
    output_image = 'combined_sets_relationship.png'
    plt.savefig(output_image, bbox_inches='tight')
    print(f"\n[+] Combined diagram saved as '{output_image}'.")
    
    print("[+] Opening the plot window...")
    plt.show()

if __name__ == "__main__":
    main()
