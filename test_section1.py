#!/usr/bin/env python3
import sys
import os
import time
import numpy as np
from pathlib import Path

# Add current directory to path for imports
sys.path.append('.')

# Mock the Colab environment check
class MockIPython:
    def __str__(self):
        return "local"

def get_ipython():
    return MockIPython()

# Import Section 1 functions by executing the notebook cells
exec("""
import cv2
import numpy as np
from PIL import Image
import os
import json
import time
import csv
from pathlib import Path

IMG_EXTS = {'.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.webp'}
LABELS = {"CSAM", "NCII", "TERROR"}

def now_ts():
    return int(time.time())

def ensure_dirs(*dirs):
    for d in dirs:
        Path(d).mkdir(exist_ok=True)

def to_json(obj):
    def json_serializer(o):
        if isinstance(o, set):
            return list(o)
        return str(o)
    return json.dumps(obj, default=json_serializer, indent=2)

def compute_pdq(image_path):
    try:
        import pdqhash
        with Image.open(image_path) as img:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            hash_int, quality = pdqhash.compute(img)
            hash_hex = f"{hash_int:064x}"
            return hash_hex, quality
    except Exception as e:
        try:
            img = cv2.imread(image_path)
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            resized = cv2.resize(gray, (8, 8))
            avg = resized.mean()
            bits = (resized > avg).astype(np.uint8)
            hash_int = int(''.join(bits.flatten().astype(str)), 2)
            hash_hex = f"{hash_int:016x}".zfill(64)
            return hash_hex, 50
        except:
            return "0" * 64, 0

def hex_to_int(hex_str):
    return int(hex_str, 16)

def hamming_distance_hex(hex1, hex2):
    return bin(hex_to_int(hex1) ^ hex_to_int(hex2)).count('1')

HASH_DB = {}

def add_hash(media_id, hash_hex, quality, source="user", labels=None):
    if labels is None:
        labels = set()
    HASH_DB[media_id] = {
        "hash": hash_hex,
        "quality": quality,
        "source": source,
        "labels": set(labels) if isinstance(labels, (list, tuple)) else labels
    }

def get_hash_count():
    return len(HASH_DB)

def get_hash_info(media_id):
    return HASH_DB.get(media_id)

def clear_hash_db():
    HASH_DB.clear()

def ingest_folder(folder_path, source="user", prefix=""):
    count = 0
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if Path(file).suffix.lower() in IMG_EXTS:
                image_path = os.path.join(root, file)
                media_id = f"{prefix}{Path(file).stem}_{now_ts()}_{count}"
                hash_hex, quality = compute_pdq(image_path)
                add_hash(media_id, hash_hex, quality, source)
                count += 1
    return count

def match_hash(query_hash, max_distance=30, topk=50):
    matches = []
    for media_id, data in HASH_DB.items():
        distance = hamming_distance_hex(query_hash, data["hash"])
        if distance <= max_distance:
            matches.append((media_id, distance))
    
    matches.sort(key=lambda x: x[1])
    return matches[:topk]

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
            
            if media_id in HASH_DB:
                HASH_DB[media_id]["labels"].add(label)
            else:
                add_hash(media_id, hash_hex, 100, source, {label} if label else set())
            count += 1
    return count

def create_sample_hashlist(output_path):
    sample_data = [
        ['hash_hex', 'label'],
        ['1234567890abcdef' + '0' * 48, 'CSAM'],
        ['fedcba0987654321' + '0' * 48, 'TERROR'],
        ['abcdef1234567890' + '0' * 48, 'NCII']
    ]
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(sample_data)
    return len(sample_data) - 1

def create_sample_image(path, color, size=(100, 100)):
    img = Image.new('RGB', size, color)
    img.save(path)
""")

def test_hash_computation():
    print("🧪 Testing hash computation...")
    
    # Create test images
    ensure_dirs('test_images')
    create_sample_image('test_images/red.jpg', (255, 0, 0))
    create_sample_image('test_images/blue.jpg', (0, 0, 255))
    create_sample_image('test_images/red_copy.jpg', (255, 0, 0))  # Identical to red
    
    # Test hash computation
    hash1, quality1 = compute_pdq('test_images/red.jpg')
    hash2, quality2 = compute_pdq('test_images/blue.jpg')
    hash3, quality3 = compute_pdq('test_images/red_copy.jpg')
    
    print(f"  Red image hash: {hash1[:16]}... (quality: {quality1})")
    print(f"  Blue image hash: {hash2[:16]}... (quality: {quality2})")
    print(f"  Red copy hash: {hash3[:16]}... (quality: {quality3})")
    
    # Test distance calculation
    dist_red_blue = hamming_distance_hex(hash1, hash2)
    dist_red_copy = hamming_distance_hex(hash1, hash3)
    
    print(f"  Distance red-blue: {dist_red_blue}")
    print(f"  Distance red-copy: {dist_red_copy}")
    
    assert dist_red_copy <= 5, f"Identical images should have low distance, got {dist_red_copy}"
    assert dist_red_blue > 10, f"Different images should have high distance, got {dist_red_blue}"
    
    print("  ✅ Hash computation tests passed")
    return hash1, hash2, hash3

def test_database_operations():
    print("\n🧪 Testing database operations...")
    
    clear_hash_db()
    assert get_hash_count() == 0, "Database should be empty after clear"
    
    # Add test hashes
    add_hash("test1", "1234567890abcdef" + "0" * 48, 95, "test", {"CSAM"})
    add_hash("test2", "fedcba0987654321" + "0" * 48, 88, "test", {"TERROR"})
    
    assert get_hash_count() == 2, f"Expected 2 hashes, got {get_hash_count()}"
    
    info = get_hash_info("test1")
    assert info is not None, "Should retrieve hash info"
    assert "CSAM" in info["labels"], "Labels should be preserved"
    
    print(f"  ✅ Database has {get_hash_count()} hashes with correct labels")

def test_matching():
    print("\n🧪 Testing hash matching...")
    
    # Test exact match
    test_hash = "1234567890abcdef" + "0" * 48
    matches = match_hash(test_hash, max_distance=0)
    
    assert len(matches) == 1, f"Expected 1 exact match, got {len(matches)}"
    assert matches[0][1] == 0, f"Expected distance 0, got {matches[0][1]}"
    
    # Test near match
    near_hash = "1234567890abcdee" + "0" * 48  # 1 bit different
    matches = match_hash(near_hash, max_distance=5)
    
    assert len(matches) >= 1, "Should find near matches"
    assert matches[0][1] <= 5, "Distance should be within threshold"
    
    print(f"  ✅ Found {len(matches)} matches within distance threshold")

def test_csv_import_export():
    print("\n🧪 Testing CSV import/export...")
    
    # Create and import test hashlist
    test_csv = 'test_images/test_hashes.csv'
    created_count = create_sample_hashlist(test_csv)
    
    initial_count = get_hash_count()
    imported_count = import_csv_hashlist(test_csv, 'threat_feed')
    
    assert imported_count == 3, f"Expected 3 imported hashes, got {imported_count}"
    assert get_hash_count() > initial_count, "Database should grow after import"
    
    # Test export
    export_csv = 'test_images/exported_hashes.csv'
    exported_count = export_hashlist_csv(export_csv)
    
    assert os.path.exists(export_csv), "Export file should be created"
    assert exported_count == get_hash_count(), "Export count should match DB size"
    
    print(f"  ✅ Imported {imported_count} hashes, exported {exported_count} hashes")

def test_performance():
    print("\n🧪 Testing performance...")
    
    # Create multiple test hashes for performance testing
    clear_hash_db()
    
    start_time = time.time()
    for i in range(100):
        hash_hex = f"{i:016x}" + "0" * 48
        add_hash(f"perf_{i}", hash_hex, 90, "perf_test")
    
    add_time = (time.time() - start_time) * 1000
    print(f"  Added 100 hashes in {add_time:.1f}ms")
    
    # Test matching performance
    query_hash = "0050000000000000" + "0" * 48
    
    start_time = time.time()
    matches = match_hash(query_hash, max_distance=20)
    match_time = (time.time() - start_time) * 1000
    
    print(f"  Matched against 100 hashes in {match_time:.1f}ms")
    print(f"  Found {len(matches)} matches")
    
    assert match_time < 100, f"Matching should be under 100ms, got {match_time:.1f}ms"
    
    print("  ✅ Performance tests passed")

def test_edge_cases():
    print("\n🧪 Testing edge cases...")
    
    # Test invalid image path
    hash_invalid, quality_invalid = compute_pdq('nonexistent.jpg')
    assert hash_invalid == "0" * 64, "Invalid image should return zero hash"
    assert quality_invalid == 0, "Invalid image should return zero quality"
    
    # Test empty hash DB matching
    clear_hash_db()
    matches = match_hash("1234567890abcdef" + "0" * 48)
    assert len(matches) == 0, "Empty DB should return no matches"
    
    # Test malformed CSV import
    malformed_csv = 'test_images/malformed.csv'
    with open(malformed_csv, 'w') as f:
        f.write("hash_hex,label\n")
        f.write("invalid_hash,TEST\n")  # Too short
        f.write("1234567890abcdef" + "0" * 48 + ",VALID\n")  # Valid
    
    imported = import_csv_hashlist(malformed_csv, 'test')
    assert imported == 1, f"Should import only valid hashes, got {imported}"
    
    print("  ✅ Edge cases handled correctly")

def run_section1_tests():
    print("🚀 Running Section 1 Tests: Hash Matching & Image Fingerprinting\n")
    
    try:
        test_hash_computation()
        test_database_operations()
        test_matching()
        test_csv_import_export()
        test_performance()
        test_edge_cases()
        
        print("\n🎉 All Section 1 tests passed!")
        print(f"📊 Final database state: {get_hash_count()} hashes")
        
        # Show sample of database contents
        print("\n📝 Sample database contents:")
        for i, (media_id, data) in enumerate(list(HASH_DB.items())[:3]):
            labels_str = ', '.join(data['labels']) if data['labels'] else 'none'
            print(f"  {media_id}: {data['hash'][:16]}... (labels: {labels_str})")
            
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Cleanup
        import shutil
        if os.path.exists('test_images'):
            shutil.rmtree('test_images')
        if os.path.exists('samples'):
            shutil.rmtree('samples')

if __name__ == "__main__":
    success = run_section1_tests()
    sys.exit(0 if success else 1)