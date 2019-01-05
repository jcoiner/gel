#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

// Protocol buffer library and generated header:
#include "google/protobuf/text_format.h"
#include "filter.pb.h"

// The git2 library:
#include "git2/merge.h"

// The cryptopp library:
#include "sha3.h"
#include "aes.h"
#include "filters.h"
#include "modes.h"

#define FLT_ASSERT(expr)                   \
  if (!(expr)) {                           \
    fprintf(stderr,"Internal error: '%s' failed at %s:%d\n",  \
            #expr, __FILE__, __LINE__);    \
    fflush(NULL);                          \
    abort();                               \
    exit(EXIT_FAILURE);                    \
  }

#define MAGIC_NAME_LEN 6
#define MAGIC_NAME "gelFLT"

constexpr bool debug = true;  // BOZO

enum Mode {
    UNKNOWN,
    CLEAN,
    SMUDGE,
    DIFF,
    MERGE,
    SELFTEST
};

using std::string;
using std::unique_ptr;
using std::unordered_map;
using std::vector;

void usage() {
    fprintf(stderr, "This is the Git Encryption Layer `filter' program.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, " > filter -mode [ clean | smudge | diff | merge |\n");
    fprintf(stderr, "                  selftest | selftest_regold ]\n");
    fprintf(stderr, "     -access_map <file>\n");
    fprintf(stderr, "     -file       <repository_path>\n");
    fprintf(stderr, "     -in         <file>\n");
    fprintf(stderr, "     -ancestor   <file>\n");
    fprintf(stderr, "     -ours       <file>\n");
    fprintf(stderr, "     -theirs     <file>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  -access_map : Must point to a file containing a text-format\n");
    fprintf(stderr, "                proto message of type AccessMap. This gives the\n");
    fprintf(stderr, "                path-to-key mapping for the current repo.\n");
    fprintf(stderr, "  -file       : Identifies the file we'll be working on by its\n");
    fprintf(stderr, "                relative path in the repo. Needed for all modes\n");
    fprintf(stderr, "                except the selftest modes.\n");
    fprintf(stderr, "  -in         : Temp file containing our input; for diff mode only.\n");
    fprintf(stderr, "  -ancestor,\n");
    fprintf(stderr, "  -ours,\n");
    fprintf(stderr, "  -theirs     : For merge mode only, these are three temp files that\n");
    fprintf(stderr, "                initially contain the inputs for the merge. Output\n");
    fprintf(stderr, "                will also be written to the 'ours' file.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "NOTE that this program is not normally user-facing! It's intended\n");
    fprintf(stderr, "to be integrated with git, and normally git should call it. For more info:\n");
    fprintf(stderr, "  https://github.com/jcoiner/gel \n");
}

static unique_ptr<filter::AccessMap> access_map;
static unordered_map<string /* keylist file */,
                     unique_ptr<filter::KeyList> > keylist_map;

static void
read_whole_file(FILE* in, string* contents) {
    FLT_ASSERT(contents->empty());

    constexpr unsigned buf_sz = 1024;
    char buf[buf_sz];
    unsigned read_count = fread(buf, 1, buf_sz, in);
    while (read_count == buf_sz) {
        contents->append(buf, read_count);
        read_count = fread(buf, 1, buf_sz, in);
    }
    if (read_count > 0) {
        contents->append(buf, read_count);
    }
    FLT_ASSERT(0 == ferror(in));
    FLT_ASSERT(1 == feof(in));
}

static void
read_whole_file(const char* filename, string* contents) {
    FILE* in = fopen(filename, "r");
    if (!in) {
        fprintf(stderr, "filter: ERROR: Cannot read %s\n", filename);
        exit(EXIT_FAILURE);
    }
    read_whole_file(in, contents);
    fclose(in);
}

static void
read_whole_file(const string& filename, string* contents) {
    read_whole_file(filename.c_str(), contents);
}

static void
write_whole_file(FILE* out, const string& contents) {
    FLT_ASSERT(contents.size() ==
               fwrite(contents.data(), 1, contents.size(), out));
}

static void
write_whole_file(const char* filename, const string& contents) {
    FILE* out = fopen(filename, "w");
    if (!out) {
        fprintf(stderr, "ERROR: Cannot write '%s'\n", filename);
        exit(EXIT_FAILURE);
    }
    write_whole_file(out, contents);
    fclose(out);
}

static void
write_whole_file(const string& filename, const string& contents) {
    write_whole_file(filename.c_str(), contents);
}

static void
check_access_map(const filter::AccessMap& map) {
    // Check that each path component given in AccessMap appears
    // to be legal.
    //
    // We don't actually check if we can read the key files, or
    // that those parse. Since we don't expect all users to have
    // access to all keys, it's not an error anyway.
    for (const auto& it : map.map()) {
        const string& path = it.first;
        FLT_ASSERT(path != ".");
        FLT_ASSERT(path != "..");
        FLT_ASSERT(NULL == strstr(path.c_str(), "/"));

        const auto& entry = it.second;
        if (entry.entry_oneof_case() == filter::AccessMap_Entry::kNext) {
            check_access_map(entry.next());
        }
    }
}

static void
read_access_map(const string& map_file) {
    FLT_ASSERT(!access_map);
    
    string map_file_text;
    read_whole_file(map_file, &map_file_text);

    access_map.reset(new filter::AccessMap);

    // BOZO should probably give a nicer err message here,
    //  since it's reasonably likely to fail on user input
    FLT_ASSERT(google::protobuf::TextFormat::
               ParseFromString(map_file_text, access_map.get()));

    // Confirm that AccessMap is well-formed.
    check_access_map( *(access_map.get()) );
}

static const filter::KeyList* readKeyList(const string& keylist_file) {
    const auto& it = keylist_map.find(keylist_file);
    if (it != keylist_map.end()) {
        return it->second.get();
    }

    keylist_map[keylist_file].reset(new filter::KeyList);
    string keylist_text;
    read_whole_file(keylist_file, &keylist_text);
    // BOZO better err msg
    FLT_ASSERT(google::protobuf::TextFormat::
               ParseFromString(keylist_text, keylist_map[keylist_file].get()));

    // Convert keys given as hex strings to raw bytes.
    for (auto& key : *(keylist_map[keylist_file]->mutable_key()) ) {
        if (!key.key_hex().empty()) {
            string key_hex = key.key_hex();
            FLT_ASSERT(key_hex.size() == 32);

            uint8_t key_bytes[16];
            memset(key_bytes, 0, 16);

            uint8_t byte = 0;
            for (unsigned i = 0; i < 32; i++) {
                char c = tolower(key_hex.at(i));
                if (c >= '0' && c <= '9') {
                    byte += (c - '0');
                } else if (c >= 'a' && c <= 'f') {
                    byte += (c - 'a') + 0xA;
                } else {
                    FLT_ASSERT(false);
                }

                if ((i & 1) == 0) {
                    byte = byte << 4;
                } else {
                    key_bytes[i >> 1] = byte;
                    byte = 0;
                }
            }

            key.set_key_bytes(key_bytes, 16);
        }
    }
    // Confirm that all keys are exactly 16 bytes, and have
    // been converted from 'key_hex' to 'key_bytes' successfully:
    for (const auto& key : keylist_map[keylist_file]->key()) {
        FLT_ASSERT(key.key_bytes().size() == 16);
    }
    return keylist_map[keylist_file].get();
}

static const filter::KeyList* findKeyList(const char* file_path,
                                          unsigned  file_path_sz,
                                          const filter::AccessMap& map) {
    // Find size of the first path component, before the first '/' character.
    unsigned first_sz;
    for (first_sz = 0; first_sz < file_path_sz; first_sz++) {
        if (file_path[first_sz] == '/') break;
    }
    FLT_ASSERT(first_sz > 0);
    FLT_ASSERT(0 != strncmp(".",  file_path, first_sz));
    FLT_ASSERT(0 != strncmp("..", file_path, first_sz));

    string first(file_path, first_sz);
    auto it = map.map().find(first);
    if (it == map.map().end()) {
        // No entry for this path -- no keyset is active,
        // data will be stored as plaintext.
        return nullptr;
    }
    const filter::AccessMap_Entry& entry = it->second;
    switch (entry.entry_oneof_case()) {
    case filter::AccessMap_Entry::kKeylistId: {
        return readKeyList(entry.keylist_id());
        break;
    }
    case filter::AccessMap_Entry::kNext: {
        const filter::AccessMap& next = entry.next();
        if (first_sz < file_path_sz) {
            // Advance first_sz past the '/' we found before.
            FLT_ASSERT(file_path[first_sz] == '/');
            first_sz++;
        }
        if (first_sz < file_path_sz) {
            // We have more path components, so recurse.
            return findKeyList(file_path + first_sz,
                               file_path_sz - first_sz,
                               next);
        }
        // We ran out of path components! So we can't key
        // into the next map, our path isn't deep enough
        // to match it. Just fail.
        return nullptr;
        break;
    }
    default: {
        FLT_ASSERT(false);
        return nullptr;
        break;
    }
    }
}

static const filter::KeyList* findKeyList(const string& file_path) {
    FLT_ASSERT(access_map);
    return findKeyList(file_path.data(), file_path.size(), *access_map);
}

static uint8_t* toBytes(char* in) {
    return reinterpret_cast<uint8_t*>(in);
}

static const uint8_t* toBytesConst(const char* in) {
    return reinterpret_cast<const uint8_t*>(in);
}

struct Blob {
    unsigned start_offset;
    uint64_t hash;
};

static void
findBlobs(const string& file_path,
          const string& plaintext,
          std::vector<Blob>* blobs) {
    FLT_ASSERT(blobs->empty());
    if (plaintext.empty()) {
        // empty file has zero blobs
        return;
    }

    Blob cur_blob;
    cur_blob.start_offset = 0;
    // hash to be determined...

    constexpr unsigned min_blob_sz = 64;

    constexpr unsigned hash_span_tiers = 3;
    constexpr unsigned hash_span[hash_span_tiers] = { 4, 16, 64 };
    constexpr unsigned bits_per_tier[hash_span_tiers] = { 3, 2, 2 };

    // Seed the hash generator with the file path.
    //
    // If we didn't do this, then identical sections of text in
    // different files would result in an identical signatures
    // of blob sizes (though not identical ciphertext)
    // and that could leak some data through to an attacker.
    //
    uint64_t init_hash = 0;
    for (unsigned i = 0; i<file_path.size(); i++) {
        init_hash = (init_hash * 31u) + file_path.at(i);
    }

    // If this invariant weren't true, we could buffer underflow below
    FLT_ASSERT( hash_span[hash_span_tiers - 1] <= min_blob_sz );

    for ( unsigned cur_idx = 0;
          cur_idx < plaintext.size();
          cur_idx++ ) {
        if ( (cur_idx - cur_blob.start_offset) <= min_blob_sz ) {
            continue;
        }

        // Logically, we want to apply some hash function to some previous
        // span of bytes to decide if we'll start a new blob at the current
        // byte. But that's possibly expensive, especially if we ever want
        // a large span.
        //
        // To reduce the cost, do it in tiers: look at just
        // hash_span[0] bytes, then only sometimes look at hash_span[1]
        // bytes and then only rarely look at the full hash_span[N] bytes.
        //
        // At each tier, we look for bits_per_tier bits in the hash output.
        // So the likelihood of matching a span is
        // 1 in 2^(bits_per_tier*hash_span_tiers)
        uint64_t hash = init_hash;
        unsigned chars_hashed = 0;
        for (unsigned tier = 0; tier < hash_span_tiers; tier++) {
            while (chars_hashed < hash_span[tier]) {
                chars_hashed++;
                // The old K&R classic:
                hash = (hash * 31u) + plaintext.at(cur_idx - chars_hashed);
            }
            if ( 0 != ( hash & ( ( 1U << bits_per_tier[tier] ) - 1 ) ) ) {
                // Don't advance to the next tier.
                goto continue_outer_loop;
            }
        }
        // Matched all tiers -- we'll start a new blob here.
        // But first, assign and retire the blob we were working on
        // that we finally have the hash for...
        cur_blob.hash = hash;
        blobs->push_back(cur_blob);

        cur_blob.start_offset = cur_idx;
        cur_blob.hash = 0;

    continue_outer_loop:
        ;
    }

    // For the final blob -- we don't have a valid hash yet,
    // so make one by going over the entire final blob, and then
    // record this blob in the list.
    uint64_t final_hash = init_hash;
    for (unsigned cur_idx = cur_blob.start_offset;
         cur_idx < plaintext.size(); cur_idx++) {
        final_hash = (final_hash * 31u) + plaintext.at(cur_idx);
    }
    cur_blob.hash = final_hash;
    blobs->push_back(cur_blob);
}

// Low level routine over AES library, decrypts one blob.
// Appends to |result| and does not require |result| to be
// initially empty.
static void
decrypt_blob(const string& key,  // 16 bytes
             const filter::Blob& blob,
             string* result) {
    FLT_ASSERT(16 == key.size());
    FLT_ASSERT(16 == blob.iv().size());
    FLT_ASSERT(16 == CryptoPP::AES::DEFAULT_KEYLENGTH);

    CryptoPP::AES::Decryption aesDecryption
        (toBytesConst(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption
        (aesDecryption, toBytesConst(blob.iv().data()));

    CryptoPP::StreamTransformationFilter stfDecryptor
        (cbcDecryption, new CryptoPP::StringSink(*result));
    stfDecryptor.Put( toBytesConst(blob.data().data()), blob.data().size() );
    stfDecryptor.MessageEnd();
}

static void
encrypt_blob(const string& key,  // 16 bytes
             const string& iv,   // 16 bytes
             const uint8_t* plaintext, size_t plaintext_sz,
             string* ciphered_blob) {
    FLT_ASSERT(16 == key.size());
    FLT_ASSERT(16 == iv.size());
    FLT_ASSERT(ciphered_blob->empty());

    FLT_ASSERT(16 == CryptoPP::AES::DEFAULT_KEYLENGTH);

    // Based on
    // https://stackoverflow.com/questions/12306956/example-of-aes-using-crypto

    CryptoPP::AES::Encryption aesEncryption
        (toBytesConst(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption
        (aesEncryption, toBytesConst(iv.data()));
    CryptoPP::StreamTransformationFilter stfEncryptor
        (cbcEncryption, new CryptoPP::StringSink(*ciphered_blob));
    stfEncryptor.Put(plaintext, plaintext_sz);
    stfEncryptor.MessageEnd();
}

static void
hash_string_to_iv(const string& in,
                  string* iv /* 16 bytes */) {
    char buf[16];
    CryptoPP::SHA3(16).CalculateDigest
        (toBytes(buf), toBytesConst(in.data()), in.size());
    iv->assign(buf, 16);
}

static bool
has_magic_prefix(const string& contents) {
    filter::CipheredFile header_only;
    header_only.set_magic_header(MAGIC_NAME, MAGIC_NAME_LEN);
    string header_bytes;
    header_only.SerializeToString(&header_bytes);

    if ( (contents.length() >= header_bytes.size()) &&
         (0 == strncmp(contents.data(),
                       header_bytes.data(), header_bytes.size())) ) {
        return true;
    }
    return false;
}

// filter_clean: top level routine implementing the encrypting "clean" filter.
//
// This routine is idempotent, since git requires its clean and smudge filters
// to be idempotent.
//
// This routine determines if a file is subject to encryption, and if so,
// what keyset should be used to encrypt.
//  FIXME:  test key rotation.
//
// For files subject to encryption, the encryption algorithm is a modification
// of the "rsyncrypt" algorithm, itself a modification of AES-based CBC.
// The goal of this algorithm is security equal to typical AES-based CBC, while
// having the property that a local change in the plaintext file results in
// a local change to the ciphered file. This permits git to "pack" multiple
// versions of the same ciphered file efficiently, using deltification.
//
// We'll derive an IV for the file from its path, and init our CBC cipher using
// this IV. When a 'trigger' function tells us to, we'll reset the CBC cipher
// with the IV. The trigger function is based on a recent window of plaintext
// data. We'll trigger at common points, even in slightly different revs of the
// same file, so many of the ciphered blocks will be common across revs.
//
static
void filter_clean(const string& file_path,
                  const string& contents,
                  string* new_contents) {
    FLT_ASSERT(new_contents->empty());

    // Can we operate the same way on either text or binary files?
    // For now assume we can.
    // Q) Will this confuse git, if the plaintext file is binary but the
    //    "cleaned" file is not?

    const filter::KeyList* key_list = findKeyList(file_path);
    if (nullptr == key_list) {
        *new_contents = contents;
        return;
    }

    // If the file has already been ciphered, pass through.
    if (has_magic_prefix(contents)) {
        *new_contents = contents;
        return;
    }

    // Compute the IV for this file.
    string file_iv;
    hash_string_to_iv(file_path, &file_iv);

    filter::CipheredFile ciphered;
    unsigned key_index = key_list->key_size() - 1;
    ciphered.set_magic_header(MAGIC_NAME, MAGIC_NAME_LEN);
    ciphered.set_key_index(key_index);
    ciphered.set_file_path(file_path);

    const string& key = key_list->key(key_index).key_bytes();
    FLT_ASSERT(key.size() == 16);

    std::vector<Blob> blobs;
    findBlobs(file_path, contents, &blobs);

    unordered_map<uint64_t /* blob hash */,
                  unsigned /* count of blobs with this hash so far */>
        blob_hash_ct;

    for (unsigned idx = 0; idx < blobs.size(); idx++) {
        unsigned offset = blobs[idx].start_offset;
        unsigned len;
        if ((idx + 1) < blobs.size()) {
            len = blobs[idx+1].start_offset - offset;
        } else {
            len = contents.size() - offset;
        }
#if 0
        printf("\nblob[%d]= ", len);
        fwrite(contents.data() + offset, 1, len, stdout);
#endif

        // Fold in the blob hash, and the count of blobs
        // with same hash seen so far, and the file_iv,
        // all together into a truly unique IV for this blob.
        //
        // Thus, even if sections of data repeat in the file,
        // we won't expose this fact to an observer without the key.
        //
        // To ensure this happens in a stable way across little/big
        // endian machines, rely on protobuf serialization:
        uint64_t hash = blobs[idx].hash;
        uint32_t hash_ct = blob_hash_ct[hash]++;

        filter::BlobIvRaw iv_raw;
        iv_raw.set_hash(hash);
        iv_raw.set_count(hash_ct);
        iv_raw.set_file_iv(file_iv);

        string blob_iv_string;
        iv_raw.SerializeToString(&blob_iv_string);

        string blob_iv;  // 16 byte digest
        hash_string_to_iv(blob_iv_string, &blob_iv);

        string ciphered_blob;
        encrypt_blob(key, blob_iv,
                     toBytesConst(contents.data() + offset), len,
                     &ciphered_blob);
        filter::Blob* bl = ciphered.add_blob();
        bl->set_data(ciphered_blob);
        bl->set_iv(blob_iv);
    }

    // Q) Does the proto library guarantee that fields will be written
    //    in field-index order? Does it guarantee that repeated elements
    //    are written in logical order? We need this stability, to avoid
    //    introducing noise in the output that would reduce git's ability
    //    to deltify storage.
    // A) Yes on both counts. Note that serialized protos are allowed to
    //    exist with fields out of field-index order, and parsers are required
    //    to parse them. Keeping fields in field-index order is a property
    //    of the proto writer library only -- not a property of the format.
    //    Whereas, repeated fields must appear in order in serialized protos,
    //    that is a property of the format.
    //
    ciphered.SerializeToString(new_contents);
}

static void
filter_smudge(const string& clean_contents,
              const string& file_path, // present for smudge; empty for diff
              string* result) {
    FLT_ASSERT(result->empty());

    if (!has_magic_prefix(clean_contents)) {
        // If file wasn't ciphered, pass it through.
        // TODO reduce copyism.
        *result = clean_contents;
        return;
    }

    filter::CipheredFile ciphered;
    FLT_ASSERT(ciphered.ParseFromString(clean_contents));

    // If we're running in smudge filter context where we expect
    // a certain file path, it should match:
    if (!file_path.empty()) {
        FLT_ASSERT(file_path == ciphered.file_path());
    }

    const filter::KeyList* key_list = findKeyList(ciphered.file_path());
    if (nullptr == key_list) {
        // TODO reduce copyism
        *result = clean_contents;
        return;
    }
    FLT_ASSERT(ciphered.key_index() < key_list->key_size());

    const string& key = key_list->key(ciphered.key_index()).key_bytes();
    FLT_ASSERT(key.size() == 16);

    for (const auto& blob : ciphered.blob()) {
        decrypt_blob(key, blob, result);
    }
}

static void
filter_diff(const string& clean_contents,
            string* result) {
    filter_smudge(clean_contents, "", result);
}

static void
setup_merge_input(const string& contents,
                  git_merge_file_input* merge_input) {
    git_merge_file_init_input(merge_input, GIT_MERGE_FILE_INPUT_VERSION);
    merge_input->ptr  = contents.data();
    merge_input->size = contents.size();
    FLT_ASSERT(merge_input->path == nullptr);
    FLT_ASSERT(merge_input->mode == 0);
}

static bool
filter_merge(const string& merge_ancestor_file,
             const string& merge_ours_file,
             const string& merge_theirs_file,
             const string& file_path) {
    string anc, ours, theirs;
    string plain_anc, plain_ours, plain_theirs;
    read_whole_file(merge_ancestor_file.c_str(), &anc);
    read_whole_file(merge_ours_file.c_str(),     &ours);
    read_whole_file(merge_theirs_file.c_str(),   &theirs);

    filter_smudge(anc,    file_path, &plain_anc);
    filter_smudge(ours,   file_path, &plain_ours);
    filter_smudge(theirs, file_path, &plain_theirs);

    git_merge_file_options fopts;
    git_merge_file_init_options(&fopts, GIT_MERGE_FILE_OPTIONS_VERSION);

    string anc_label = string("ORIGINAL @ ") + file_path;
    fopts.ancestor_label = anc_label.c_str();
    string ours_label = string("YOURS @ ") + file_path;
    fopts.our_label = ours_label.c_str();
    string theirs_label = string("THEIRS @ ") + file_path;
    fopts.their_label = theirs_label.c_str();

    git_merge_file_input anci;
    git_merge_file_input oursi;
    git_merge_file_input theirsi;
    setup_merge_input(plain_anc,    &anci);
    setup_merge_input(plain_ours,   &oursi);
    setup_merge_input(plain_theirs, &theirsi);

    git_merge_file_result result;
    int status = git_merge_file(&result, &anci, &oursi, &theirsi, &fopts);
    if (status != 0) {
        // Q: Do we get here on a run-of-the-mill conflict?
        //    If so we don't want to exit yet...
        // A: Empirically: no we don't get here in a typical
        //    conflict case.
        fprintf(stderr, "filter: ERROR: 3way merge failed "
                "at git_merge_file(). stop.\n");

        // Q: Do we need to use git_merge_file_result_free()
        //    after git_merge_file() fails? I assume not, for now.
        return false;
    }

    string merged_plain(result.ptr, result.len); // extra copy... sorry
    string merged;
    filter_clean(file_path, merged_plain, &merged);
    write_whole_file(merge_ours_file.c_str(), merged);

    bool return_status = result.automergeable;
    git_merge_file_result_free(&result);
    return return_status;
}

static void
test_round_trip(const char* plaintext_filename) {
    string plaintext;
    read_whole_file(plaintext_filename, &plaintext);

    string ciphered_text;
    string path("secret/file");
    filter_clean(path,
                 plaintext,
                 &ciphered_text);

    string cipher_filename;
    cipher_filename.append("out/");
    cipher_filename.append(plaintext_filename);
    cipher_filename.append(".clean");
    write_whole_file(cipher_filename.c_str(), ciphered_text);

    // Test idempotency of clean operation
    string doubly_ciphered_text;
    filter_clean(path,
                 ciphered_text,
                 &doubly_ciphered_text);
    FLT_ASSERT(doubly_ciphered_text == ciphered_text);

    // Smudge (decrypt) the cleaned (ciphered) contents
    string plaintext_smudge_out;
    filter_smudge(ciphered_text,
                  path,
                  &plaintext_smudge_out);
    FLT_ASSERT(plaintext_smudge_out == plaintext);

    // Test the diff (decrypt) routine which is slightly
    // different than the smudge routine
    string plaintext_diff_out;
    filter_diff(ciphered_text,
                &plaintext_diff_out);
    FLT_ASSERT(plaintext_diff_out == plaintext);

    // Test idempotency of smudge operation
    string doubly_smudged_text;
    filter_smudge(plaintext,
                  path,
                  &doubly_smudged_text);
    FLT_ASSERT(doubly_smudged_text == plaintext);

    printf("round_trip OK: %s\n", plaintext_filename);
}

// Return name of tmp file corresponding to |in_file|,
// for use in the merge test. Where |in_file| is the
// plaintext source file for the test, and the tmp file
// is optionally ciphered based on |fake_path|.
static string test_merge_input(const string& in_file,
                               const string& fake_path) {
    string in_text;
    read_whole_file(in_file, &in_text);

    string tmp_file;
    tmp_file.append("out/");
    tmp_file.append(in_file);

    string repo_contents;
    filter_clean(fake_path, in_text, &repo_contents);

    write_whole_file(tmp_file, repo_contents);
    return tmp_file;
}

static void test_merge(const string& anc_file,
                       const string& ours_file,
                       const string& theirs_file,
                       const string& expected_result_file,
                       bool expect_auto_merge_ok,
                       bool apply_crypto,
                       bool regold) {
    string fake_path(apply_crypto
                     ? "secret/file"
                     : "somewhere/else/file");
    string tmp_anc_file = test_merge_input(anc_file, fake_path);
    string tmp_ours_file = test_merge_input(ours_file, fake_path);
    string tmp_theirs_file = test_merge_input(theirs_file, fake_path);

    // Call the merge function
    bool ok = filter_merge(tmp_anc_file,
                           tmp_ours_file,
                           tmp_theirs_file,
                           fake_path);
    FLT_ASSERT(ok == expect_auto_merge_ok);

    string merge_result;
    string merge_result_expect;
    read_whole_file(tmp_ours_file, &merge_result);

    if (apply_crypto) {
        // The merge result should be ciphered in this case.
        FLT_ASSERT(has_magic_prefix(merge_result));
    } else {
        FLT_ASSERT(!has_magic_prefix(merge_result));
    }

    // Possibly decipher the merge result
    string merge_result_plaintext;
    filter_smudge(merge_result, fake_path, &merge_result_plaintext);

    if (regold) {
        write_whole_file(expected_result_file, merge_result_plaintext);
    } else {
        read_whole_file(expected_result_file, &merge_result_expect);
        FLT_ASSERT(merge_result_plaintext == merge_result_expect);
    }

    printf("test_merge OK: expect_auto_merge_ok = %s, apply_crypto = %s\n",
           expect_auto_merge_ok ? "true" : "false",
           apply_crypto         ? "true" : "false");
}

// Produce a hex dump for a ciphered file.
// Assumes that 'in_file' is below the out/ directory already.
static string
hex_dump(const string& in_file) {
    string in_text;
    read_whole_file(in_file, &in_text);
    FLT_ASSERT(has_magic_prefix(in_text));

    string dump_file = in_file + ".dump";
    FILE* dump = fopen(dump_file.c_str(), "w");
    for(unsigned i = 0; i < in_text.size(); i++) {
        fprintf(dump, "%x\n", (unsigned char)(in_text.at(i)));
    }
    fclose(dump);
    return dump_file;
}

static unsigned
file_size(const string& file) {
    struct stat stbuf;
    int status = lstat(file.c_str(), &stbuf);
    FLT_ASSERT(status == 0);
    return stbuf.st_size;
}

static void
test_compact_diffs(const string& fileA,
                   const string& fileB) {
    string a_dump = hex_dump(fileA);
    string b_dump = hex_dump(fileB);

    string diff_out_file = a_dump + ".diff_out";
    string cmd = string("diff ") + a_dump + " " + b_dump + " > " + diff_out_file;
    int status = system(cmd.c_str());
    FLT_ASSERT(status != 0); // we expect diff to fail...

    unsigned a_sz = file_size(a_dump);
    unsigned diff_sz = file_size(diff_out_file);

    // Binary diffs should be compact.
    //
    // Note, since the diff file tends to repeat each differing section
    // twice (once for OURS and once for THEIRS) the diff output exaggerates
    // the actual amount of difference, it's really less than this 50% factor:
    FLT_ASSERT((diff_sz * 2) < a_sz);

    printf("confirm_compact_diffs OK\n");
}

static void
test_stable_smudge(const string& old_ciphered_file,
                   const string& expect_plaintext_file) {
    string ciphered_text;
    read_whole_file(old_ciphered_file, &ciphered_text);

    string plaintext_out;
    filter_smudge(ciphered_text,
                  "secret/file",
                  &plaintext_out);

    string expect_plaintext;
    read_whole_file(expect_plaintext_file, &expect_plaintext);
    FLT_ASSERT(expect_plaintext == plaintext_out);
}

static void
test_semantic_security() {
    // In a single file with repeating text, ensure we produce unique
    // IVs for each blob.

    string plaintext;
    for (unsigned i = 0; i < 256; i++) {
        // Oops: this text doesn't trigger any blob starts! which we need for this
        // test to work.
        //plaintext.append("All work and no play makes Jack a dull boy.\n");
        // This text has at least one blob trigger:
        plaintext.append("Though the spirit of the proverb had been expressed previously, the modern saying appeared first in James Howell's Proverbs in English, Italian, French and Spanish (1659),[1] and was included in later collections of proverbs. It also appears in Howell's Paroimiographia (1659), p. 12. ");
    }
    string ciphertext;
    filter_clean("secret/file", plaintext, &ciphertext);

    // Ensure that no two blobs have the same IV.
    filter::CipheredFile ciphered;
    FLT_ASSERT(ciphered.ParseFromString(ciphertext));

    std::unordered_set<string> ivs;
    unsigned ct = 0;
    for (const auto& blob : ciphered.blob()) {
        FLT_ASSERT(ivs.find(blob.iv()) == ivs.end());
        ivs.insert(blob.iv());
        ct++;
    }
    // Double check that we really got a large set of blobs.
    FLT_ASSERT(ct > 127);
}

static void selftest(bool regold) {
    // For each file, cipher it and decipher it.
    //
    test_round_trip("decl1.txt");
    test_round_trip("decl2.txt");
    test_round_trip("decl3.txt");

    // We expect that since plaintext is similar across
    // decl1/2/3, the ciphertext should not differ hugely either.
    // This is what will allow git to deltify edits and store
    // them efficiently. Check on this:
    test_compact_diffs("out/decl1.txt.clean",
                       "out/decl2.txt.clean");
    test_compact_diffs("out/decl2.txt.clean",
                       "out/decl3.txt.clean");

    // I's very important that we have a stable smudge operation for
    // old pre-existing cleaned files that are stored in git.
    // Older files might have been encrypted using older keys in the
    // same keyset; they might use older versions of the proto; etc.
    //
    // The 'test_round_trip' doesn't cover this, since it's driven
    // off plaintext files only and produces new ciphered text on
    // each run.
    //
    // This test fills that gap -- it uses a checked-in ciphered
    // file, and smudges it, to confirm the operation is stable across
    // code changes. No automatic regold is provided because if it
    // ever fails, WHAT ARE YOU DOING, proceed with caution.
    //
    // TODO: key rotation isn't tested yet, we're not covering the case
    // where the ciphered file was ciphered using a retired key.
    test_stable_smudge("decl1.txt.old.clean",
                       "decl1.txt");

    test_merge("merge_anc.txt",
               "merge_ours.txt",
               "merge_theirs.txt",
               "merge_result.txt",
               true  /* expect auto merge ok */,
               false /* apply encrypt/decrpyt */,
               regold);
    test_merge("merge_anc.txt",
               "merge_ours.txt",
               "merge_theirs.txt",
               "merge_result.txt",
               true  /* expect auto merge ok */,
               true  /* apply encrypt/decrpyt */,
               regold);
    test_merge("merge_anc.txt",
               "merge_ours.txt",
               "merge_theirs2.txt",
               "merge_result2a.txt",
               false  /* expect auto merge ok */,
               false  /* apply encrypt/decrypt */,
               regold);
    test_merge("merge_anc.txt",
               "merge_ours.txt",
               "merge_theirs2.txt",
               "merge_result2b.txt",
               false  /* expect auto merge ok */,
               true   /* apply encrypt/decrypt */,
               regold);

    // Merge some binary files.
    //
    // I used the 'bless' hex editor to put a few random bytes
    // into anc/ours/theirs -- it's just garbage, the contents are not
    // significant except that they are different.
    //
    // Also note, 'merge_result.bin' is empty. For some reason, our
    // merge routine produces empty output when we ask it to merge
    // binaries.
    //
    // Plugging this merge driver into git, and doing a live merge with
    // real binaries, we get this behavior:
    //
    // Git will understand (based on exit code) that the merge failed.
    // User will see a zero byte file after the failed merge, and git
    // will instruct them to resolve the conflict and 'git add' the file
    // to resolve the merge. In this state, both "git mergetool" and
    // "git checkout --ours/--theirs" work as usual.
    //
    // I don't think raw git would leave a zero byte file, so this isn't
    // perfectly transparent, but it's not awful either. For now let's
    // just hang this change-detector test on it and call it good enough.
    test_merge("merge_anc.bin",
               "merge_ours.bin",
               "merge_theirs.bin",
               "merge_result.bin",
               false  /* expect auto merge ok */,
               true   /* apply encrypt/decrypt */,
               regold);
    test_merge("merge_anc.bin",
               "merge_ours.bin",
               "merge_theirs.bin",
               "merge_result.bin",
               false,  // expect auto merge ok
               false,  // apply encrypt/decrypt
               regold);

    // Confirm that an input file with repeating sections does
    // not produce repeating sections in the ciphered file.
    test_semantic_security();
}

static bool string_arg(int* ip,
                int argc, char** argv,
                const char* arg_name,
                string* value) {
    if (0 == strcmp(arg_name, argv[*ip])) {
        (*ip)++;
        if ((*ip) >= argc) {
            usage();
            exit(EXIT_FAILURE);
        }
        value->assign(argv[*ip]);
        return true;
    }
    return false;
}

int main(int argc, char** argv) {
    Mode mode = UNKNOWN;
    string file_path;
    string input_file;
    string access_map_file;
    string merge_ancestor_file, merge_ours_file, merge_theirs_file;
    bool selftest_regold = false;

    if (debug) {
        fprintf(stderr, " > filter ");
        for (int i = 1; i < argc; i++) {
            fprintf(stderr, " %s", argv[i]);
        }
        fprintf(stderr, "\n");
    }

    for (int i = 1; i < argc; i++) {
        if ( (0 == strcmp("-h", argv[i])) ||
             (0 == strcmp("-help", argv[i])) ||
             (0 == strcmp("--help", argv[i])) ) {
            usage();
            exit(EXIT_SUCCESS);
        }
        if (0 == strcmp("-mode", argv[i])) {
            i++;
            if (i >= argc) {
                usage();
                exit(EXIT_FAILURE);
            }
            if (0 == strcmp("clean", argv[i])) {
                mode = CLEAN;
            } else if (0 == strcmp("smudge", argv[i])) {
                mode = SMUDGE;
            } else if (0 == strcmp("diff", argv[i])) {
                mode = DIFF;
            } else if (0 == strcmp("merge", argv[i])) {
                mode = MERGE;
            } else if (0 == strcmp("selftest", argv[i])) {
                // NOTE: self test mode assumes filter.cc is running
                //       in its own dev tree's "test/" directory...
                mode = SELFTEST;
            } else if (0 == strcmp("selftest_regold", argv[i])) {
                mode = SELFTEST;
                selftest_regold = true;
            } else {
                usage();
                exit(EXIT_FAILURE);
            }
        }
        else if (string_arg(&i, argc, argv, "-access_map", &access_map_file)) { }
        else if (string_arg(&i, argc, argv, "-file", &file_path))             { }
        // Textconv (diff) specifies input in a file, not stdin
        // because git is not great at consistency
        else if (string_arg(&i, argc, argv, "-in", &input_file))              { }
        // Merge has extra args...
        else if (string_arg(&i, argc, argv, "-ancestor", &merge_ancestor_file)) { }
        else if (string_arg(&i, argc, argv, "-ours",     &merge_ours_file))     { }
        else if (string_arg(&i, argc, argv, "-theirs",   &merge_theirs_file))   { }
        else {
            usage();
            exit(EXIT_FAILURE);
        }
    }

    // Check for required options
    if ((mode != DIFF) && (mode != SELFTEST) && file_path.empty()) {
        usage();
        exit(EXIT_FAILURE);
    }
    if (access_map_file.empty()) {
        usage();
        exit(EXIT_FAILURE);
    }

    // We need the access map before we can process anything
    read_access_map(access_map_file);

    switch (mode) {
    case CLEAN: {
        // Clean will encrypt certain secret files.
        // Our behavior here depends on whether the file is text or binary
        // (TBD -- really? not yet it doesn't...)
        // and whether it's in a protected directory where we must encrypt.
        string contents;
        read_whole_file(stdin, &contents);

        // JPC: design this API so we can keep it when we switch to
        // a 'process' type filter (long lived process)
        string new_contents;
        filter_clean(file_path, contents, &new_contents);
        if (!new_contents.empty()) {
            fwrite(new_contents.data(), new_contents.size(), 1, stdout);
        }
        break;
    }
    case SMUDGE: {
        // Smudge will decrypt files that were stored encrypted.
        //
        string in, out;
        read_whole_file(stdin, &in);
        filter_smudge(in, file_path, &out);
        if (!out.empty()) {
            fwrite(out.data(), out.size(), 1, stdout);
        }
        break;
    }
    case DIFF: {
        string in, out;
        read_whole_file(input_file.c_str(), &in);
        filter_diff(in, &out);
        if (!out.empty()) {
            fwrite(out.data(), out.size(), 1, stdout);
        }
        break;
    }
    case MERGE: {
        bool ok = filter_merge(merge_ancestor_file,
                               merge_ours_file,
                               merge_theirs_file,
                               file_path);
        exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
        break;
    }
    case SELFTEST: {
        selftest(selftest_regold);
        break;
    }
    default:
        usage();
        exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}
