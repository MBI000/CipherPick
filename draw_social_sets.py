import matplotlib.pyplot as plt
import matplotlib.patches as patches

def main():
    # 1. Define the Universal Set logic
    # Representing approximately 4000+ social media platforms worldwide
    universal_size = 4000
    
    # 2. Define the Subset (The 22 specific targets from Username Hunter)
    hunter_subset = {
        "Facebook", "Instagram", "X (Twitter)", "YouTube", "TikTok", 
        "Pinterest", "Twitch", "Snapchat", "LinkedIn", "Medium", 
        "GitHub", "Reddit", "HackerNews", "Vimeo", "GitLab", 
        "Flickr", "Dev.to", "Patreon", "Spotify", "Pastebin", 
        "Roblox", "Wikipedia"
    }
    
    print(f"Total platforms in Universal Set (U): ~{universal_size}")
    print(f"Total targeted platforms in Subset (C): {len(hunter_subset)}")

    # 3. Use Matplotlib to draw the relationship
    fig, ax = plt.subplots(figsize=(10, 10))
    
    # Draw Universal Set as a large green circle
    universal_circle = patches.Circle(
        (0.5, 0.5), 0.45, 
        fill=True, color='lightgreen', alpha=0.5, 
        label=f'Universal Set (U)\nAll Social Platforms\nSize: ~{universal_size}'
    )
    ax.add_patch(universal_circle)
    
    # Draw Common Ports Subset as a smaller dark green circle inside
    subset_circle = patches.Circle(
        (0.5, 0.35), 0.25, 
        fill=True, color='seagreen', alpha=0.9, 
        label=f'Subset (C)\nOSINT Hunter Targets\nSize: {len(hunter_subset)}'
    )
    ax.add_patch(subset_circle)
    
    # Add textual annotations inside the sets
    ax.text(0.5, 0.8, 'Universal Set (U)\nThousands of global social networks, forums,\nand niche communities (e.g., VK, Weibo, Mastodon...)', 
            ha='center', va='center', fontsize=11, fontweight='bold', color='darkgreen')
            
    # Format the 22 platforms nicely for the inner circle
    subset_text = "Subset (C) - 22 Most Used\n\n"
    subset_text += "Facebook, Instagram, X (Twitter)\n"
    subset_text += "YouTube, TikTok, Pinterest\n"
    subset_text += "Twitch, Snapchat, LinkedIn\n"
    subset_text += "Medium, GitHub, Reddit...\n"
    
    ax.text(0.5, 0.35, subset_text, 
            ha='center', va='center', fontsize=10, fontweight='bold', color='white')
    
    # Configure the plot window
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off') # Hide axes
    
    plt.title('Set Theory: Global Social Media vs Username Hunter Targets', fontsize=16, fontweight='bold')
    plt.legend(loc='upper right', bbox_to_anchor=(1.15, 1))
    
    # Save the output image and display the plot
    output_image = 'social_media_sets.png'
    plt.savefig(output_image, bbox_inches='tight')
    print(f"\n[+] Venn diagram saved as '{output_image}'.")
    
    print("[+] Opening the plot window...")
    plt.show()

if __name__ == "__main__":
    main()
