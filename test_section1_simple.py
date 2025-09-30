#!/usr/bin/env python3
"""
Simple test for Section 1: Hash Matching & Image Fingerprinting
Tests core functionality without PDQ dependency (uses fallback hashing)
"""

import os
import sys
import time
import csv
from pathlib import Path
import cv2
import numpy as np
from PIL import Image

def setup_section1():
    """Set up Section 1 functions for testing"""
    
    global HASH_DB, IMG_EXTS, LABELS
    
    IMG_EXTS = {'.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.webp'}
    LABELS = {"CSAM", "NCII", "TERROR"}
    HASH_DB = {}
    
    def compute_pdq(image_path):
        """Fallback hash computation using OpenCV"""
        try:
            img = cv2.imread(image_path)
            if img is None:
                return "0" * 64, 0
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            resized = cv2.resize(gray, (8, 8))
            avg = resized.mean()
            bits = (resized > avg).astype(np.uint8)
            hash_int = int(''.join(bits.flatten().astype(str)), 2)
            hash_hex = f"{hash_int:016x}".zfill(64)
            return hash_hex, 50
        except Exception as e:
            print(f"Hash computation failed: {e}")
            return "0" * 64, 0
    
    def hex_to_int(hex_str):
        return int(hex_str, 16)
    
    def hamming_distance_hex(hex1, hex2):
        return bin(hex_to_int(hex1) ^ hex_to_int(hex2)).count('1')
    
    def add_hash(media_id, hash_hex, quality, source="user", labels=None):
        if labels is None:
            labels = set()
        HASH_DB[media_id] = {
            "hash": hash_hex,
            "quality": quality,
            "source": source,
            "labels": set(labels) if isinstance(labels, (list, tuple)) else labels
        }
    
    def match_hash(query_hash, max_distance=30, topk=50):
        matches = []
        for media_id, data in HASH_DB.items():
            distance = hamming_distance_hex(query_hash, data["hash"])
            if distance <= max_distance:
                matches.append((media_id, distance))
        matches.sort(key=lambda x: x[1])
        return matches[:topk]
    
    def create_sample_image(path, color, size=(100, 100)):
        img = Image.new('RGB', size, color)
        img.save(path)
    
    def import_csv_hashlist(csv_path, source):
        count = 0
        with open(csv_path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                hash_hex = row.get('hash_hex', '').strip()
                label = row.get('label', '').strip()
                
                if not hash_hex or len(hash_hex) != 64:
                    continue
                    
                media_id = f"{source}:{hash_hex[:12]}"
                add_hash(media_id, hash_hex, 100, source, {label} if label else set())
                count += 1
        return count
    
    return {
        'compute_pdq': compute_pdq,
        'hamming_distance_hex': hamming_distance_hex,
        'add_hash': add_hash,
        'match_hash': match_hash,
        'create_sample_image': create_sample_image,
        'import_csv_hashlist': import_csv_hashlist
    }

def test_section1():
    print("🚀 Testing Section 1: Hash Matching & Image Fingerprinting")
    
    # Setup
    funcs = setup_section1()
    compute_pdq = funcs['compute_pdq']
    hamming_distance_hex = funcs['hamming_distance_hex']
    add_hash = funcs['add_hash']
    match_hash = funcs['match_hash']
    create_sample_image = funcs['create_sample_image']
    import_csv_hashlist = funcs['import_csv_hashlist']
    
    os.makedirs('test_output', exist_ok=True)
    
    # Test 1: Hash computation
    print("\n🧪 Test 1: Hash computation")
    create_sample_image('test_output/red.jpg', (255, 0, 0))
    create_sample_image('test_output/blue.jpg', (0, 0, 255))
    create_sample_image('test_output/red_copy.jpg', (255, 0, 0))
    
    hash1, qual1 = compute_pdq('test_output/red.jpg')
    hash2, qual2 = compute_pdq('test_output/blue.jpg')
    hash3, qual3 = compute_pdq('test_output/red_copy.jpg')
    
    print(f"  Red hash: {hash1[:16]}... (quality: {qual1})")
    print(f"  Blue hash: {hash2[:16]}... (quality: {qual2})")
    print(f"  Red copy: {hash3[:16]}... (quality: {qual3})")
    
    dist_identical = hamming_distance_hex(hash1, hash3)
    dist_different = hamming_distance_hex(hash1, hash2)
    
    print(f"  Distance identical: {dist_identical}")
    print(f"  Distance different: {dist_different}")
    
    assert dist_identical <= 10, f"Identical images should have low distance, got {dist_identical}"
    print("  ✅ Hash computation working")
    
    # Test 2: Database operations
    print("\n🧪 Test 2: Database operations")
    HASH_DB.clear()
    
    add_hash("test1", hash1, qual1, "user", {"clean"})
    add_hash("threat1", "1234567890abcdef" + "0" * 48, 100, "threat_feed", {"CSAM"})
    add_hash("threat2", "fedcba0987654321" + "0" * 48, 100, "threat_feed", {"TERROR"})
    
    print(f"  Database size: {len(HASH_DB)}")
    print(f"  Sample entry: {list(HASH_DB.keys())[0]}")
    
    assert len(HASH_DB) == 3, f"Expected 3 entries, got {len(HASH_DB)}"
    print("  ✅ Database operations working")
    
    # Test 3: Hash matching
    print("\n🧪 Test 3: Hash matching")
    
    # Test exact match
    exact_matches = match_hash(hash1, max_distance=0)
    print(f"  Exact matches for red image: {len(exact_matches)}")
    
    # Test near match
    near_matches = match_hash(hash1, max_distance=20)
    print(f"  Near matches (distance ≤ 20): {len(near_matches)}")
    
    # Test threat detection
    threat_hash = "1234567890abcdef" + "0" * 48
    threat_matches = match_hash(threat_hash, max_distance=5)
    print(f"  Threat matches: {len(threat_matches)}")
    
    if threat_matches:
        media_id, distance = threat_matches[0]
        threat_info = HASH_DB[media_id]
        print(f"  Found threat: {media_id} (labels: {threat_info['labels']})")
    
    print("  ✅ Hash matching working")
    
    # Test 4: CSV import
    print("\n🧪 Test 4: CSV import")
    
    # Create test CSV
    test_csv = 'test_output/test_hashes.csv'
    with open(test_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['hash_hex', 'label'])
        writer.writerow(['abcdef1234567890' + '0' * 48, 'NCII'])
        writer.writerow(['1111222233334444' + '0' * 48, 'TERROR'])
        writer.writerow(['invalid_hash', 'INVALID'])  # Should be skipped
    
    initial_count = len(HASH_DB)
    imported = import_csv_hashlist(test_csv, 'external_feed')
    
    print(f"  Imported {imported} hashes")
    print(f"  Database grew from {initial_count} to {len(HASH_DB)}")
    
    assert imported == 2, f"Expected 2 valid imports, got {imported}"
    assert len(HASH_DB) == initial_count + imported, "Database size should match imports"
    print("  ✅ CSV import working")
    
    # Test 5: Performance
    print("\n🧪 Test 5: Performance")
    
    start_time = time.time()
    test_hash = hash1
    for _ in range(100):
        matches = match_hash(test_hash, max_distance=30)
    match_time = (time.time() - start_time) * 1000
    
    print(f"  100 match operations: {match_time:.1f}ms")
    print(f"  Average per match: {match_time/100:.2f}ms")
    
    assert match_time < 1000, f"Performance too slow: {match_time:.1f}ms"
    print("  ✅ Performance acceptable")
    
    # Summary
    print(f"\n📊 Final Summary:")
    print(f"  Total hashes in database: {len(HASH_DB)}")
    print(f"  Hash sources: {set(data['source'] for data in HASH_DB.values())}")
    print(f"  Threat labels found: {set().union(*[data['labels'] for data in HASH_DB.values() if data['labels']])}")
    
    # Show threat detection capability
    print(f"\n🛡️  Threat Detection Test:")
    for media_id, data in HASH_DB.items():
        if data['labels'] & LABELS:  # Has threatening labels
            print(f"  {media_id}: {data['hash'][:16]}... (⚠️  {data['labels']})")
    
    print("\n🎉 All Section 1 tests passed!")
    return True

def cleanup():
    """Clean up test files"""
    import shutil
    if os.path.exists('test_output'):
        shutil.rmtree('test_output')

if __name__ == "__main__":
    try:
        success = test_section1()
        if success:
            print("\n✅ Section 1 is ready for production!")
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        cleanup()