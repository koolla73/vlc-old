#include "Ap4Decrypt.hpp"
#include "Ap4.h"

#include <vlc_block.h>


static constexpr const unsigned int AP4_SPLIT_MAX_TRACK_IDS = 32;

struct Options {
	const char*  pattern_params;
	unsigned int start_number;
	unsigned int track_ids[AP4_SPLIT_MAX_TRACK_IDS];
	unsigned int track_id_count;
} Options;

static bool TrackIdMatches(unsigned int track_id)
{
	if (Options.track_id_count == 0) return true;
	for (unsigned int i = 0; i < Options.track_id_count; i++) {
		if (Options.track_ids[i] == track_id) return true;
	}

	return false;
}

void AP4_Decrypt::decrypt(void** fragment, const char* keyId, const char* key) {

    block_t** segment = reinterpret_cast<block_t**>(fragment);
	if (strlen(keyId) != 32 || strlen(key) != 32) {
		return;
	}

	unsigned char keyID[16];
	unsigned char decryptionKey[16];
	AP4_ParseHex(keyId, keyID, 16);
	AP4_ParseHex(key, decryptionKey, 16);

	AP4_ProtectionKeyMap keyMap;
	keyMap.SetKeyForKid(keyID, decryptionKey, 16);

	AP4_MemoryByteStream* inputBuffer = new AP4_MemoryByteStream((*segment)->p_buffer, (*segment)->i_buffer);
	AP4_MemoryByteStream* decryptedOutputBuffer = new AP4_MemoryByteStream();
	AP4_CencDecryptingProcessor* processor = new AP4_CencDecryptingProcessor(&keyMap);

	const AP4_Result result = processor->Process(*inputBuffer, *decryptedOutputBuffer);

	delete processor;
	inputBuffer->Release();

	if (AP4_FAILED(result)) {
		decryptedOutputBuffer->Release();
		return;
	}

    *segment = block_Realloc(*segment, 0, decryptedOutputBuffer->GetDataSize());
    if (*segment != NULL)
    {
        memcpy((*segment)->p_buffer, decryptedOutputBuffer->GetData(), decryptedOutputBuffer->GetDataSize());
    }

	decryptedOutputBuffer->Release();
}

void AP4_Decrypt::split(void** fragment, uint8_t** initData, size_t& initSize) {

    block_t** segment = reinterpret_cast<block_t**>(fragment);
	AP4_Result result;
	Options.pattern_params = "IN";
	Options.start_number = 1;
	Options.track_id_count = 0;

	AP4_MemoryByteStream* input = new AP4_MemoryByteStream((*segment)->p_buffer, (*segment)->i_buffer);
	AP4_File* file = new AP4_File(*input, true);
	AP4_Movie* movie = file->GetMovie();
	if (movie == NULL) {
		delete file;
		input->Release();
		return;
	}

	AP4_MemoryByteStream* output = new AP4_MemoryByteStream();

	AP4_FtypAtom* ftyp = file->GetFileType();
	if (ftyp) {
		result = ftyp->Write(*output);
		if (AP4_FAILED(result)) {
			delete file;
			input->Release();
			output->Release();
			return;
		}
	}

	result = movie->GetMoovAtom()->Write(*output);
	if (AP4_FAILED(result)) {
		delete file;
		input->Release();
		output->Release();
		return;
	}

	initSize = output->GetDataSize();
	*initData = (uint8_t*)malloc(initSize);
	memcpy(*initData, output->GetData(), initSize);

	AP4_Atom* atom = NULL;
	unsigned int track_id = 0;
	AP4_DefaultAtomFactory atom_factory;
	for (;;) {
		// process the next atom
		result = atom_factory.CreateAtomFromStream(*input, atom);
		if (AP4_FAILED(result)) break;

		if (atom->GetType() == AP4_ATOM_TYPE_MOOF) {
			AP4_ContainerAtom* moof = AP4_DYNAMIC_CAST(AP4_ContainerAtom, atom);

			unsigned int traf_count = 0;
			AP4_ContainerAtom* traf = NULL;
			do {
				traf = AP4_DYNAMIC_CAST(AP4_ContainerAtom, moof->GetChild(AP4_ATOM_TYPE_TRAF, traf_count));
				if (traf == NULL) break;
				AP4_TfhdAtom* tfhd = AP4_DYNAMIC_CAST(AP4_TfhdAtom, traf->GetChild(AP4_ATOM_TYPE_TFHD));
				if (tfhd == NULL) {
					delete file;
					input->Release();
					output->Release();
					return;
				}
				track_id = tfhd->GetTrackId();
				traf_count++;
			} while (traf);

			// check if this fragment has more than one traf
			if (traf_count > 1) {
				track_id = 0;
			}

			// open a new file for this fragment if this moof is a segment start
			if (Options.track_id_count == 0 || track_id == Options.track_ids[0]) {
				if (output) {
					output->Release();
					output = NULL;
				}

				output = new AP4_MemoryByteStream();
			}
		}

		// write the atom
		if (output && atom->GetType() != AP4_ATOM_TYPE_MFRA && TrackIdMatches(track_id)) {
			atom->Write(*output);
		}
		delete atom;
	}
	
	*segment = block_Realloc(*segment, 0, output->GetDataSize());
    if (*segment != NULL)
    {
        memcpy((*segment)->p_buffer, output->GetData(), output->GetDataSize());
    }

	delete file;
	if (input) input->Release();
	if (output) output->Release();
}

void AP4_Decrypt::split(void** fragment) {

    block_t** segment = reinterpret_cast<block_t**>(fragment);
	AP4_Result result;
	Options.pattern_params = "IN";
	Options.start_number = 1;
	Options.track_id_count = 0;

	AP4_MemoryByteStream* input = new AP4_MemoryByteStream((*segment)->p_buffer, (*segment)->i_buffer);
	AP4_File* file = new AP4_File(*input, true);
	AP4_Movie* movie = file->GetMovie();
	if (movie == NULL) {
		delete file;
		input->Release();
		return;
	}

	AP4_MemoryByteStream* output = new AP4_MemoryByteStream();

	AP4_FtypAtom* ftyp = file->GetFileType();
	if (ftyp) {
		result = ftyp->Write(*output);
		if (AP4_FAILED(result)) {
			delete file;
			input->Release();
			output->Release();
			return;
		}
	}

	result = movie->GetMoovAtom()->Write(*output);
	if (AP4_FAILED(result)) {
		delete file;
		input->Release();
		output->Release();
		return;
	}

	AP4_Atom* atom = NULL;
	unsigned int track_id = 0;
	AP4_DefaultAtomFactory atom_factory;
	for (;;) {
		// process the next atom
		result = atom_factory.CreateAtomFromStream(*input, atom);
		if (AP4_FAILED(result)) break;

		if (atom->GetType() == AP4_ATOM_TYPE_MOOF) {
			AP4_ContainerAtom* moof = AP4_DYNAMIC_CAST(AP4_ContainerAtom, atom);

			unsigned int traf_count = 0;
			AP4_ContainerAtom* traf = NULL;
			do {
				traf = AP4_DYNAMIC_CAST(AP4_ContainerAtom, moof->GetChild(AP4_ATOM_TYPE_TRAF, traf_count));
				if (traf == NULL) break;
				AP4_TfhdAtom* tfhd = AP4_DYNAMIC_CAST(AP4_TfhdAtom, traf->GetChild(AP4_ATOM_TYPE_TFHD));
				if (tfhd == NULL) {
					delete file;
					input->Release();
					output->Release();
					return;
				}
				track_id = tfhd->GetTrackId();
				traf_count++;
			} while (traf);

			// check if this fragment has more than one traf
			if (traf_count > 1) {
				track_id = 0;
			}

			// open a new file for this fragment if this moof is a segment start
			if (Options.track_id_count == 0 || track_id == Options.track_ids[0]) {
				if (output) {
					output->Release();
					output = NULL;
				}

				output = new AP4_MemoryByteStream();
			}
		}

		// write the atom
		if (output && atom->GetType() != AP4_ATOM_TYPE_MFRA && TrackIdMatches(track_id)) {
			atom->Write(*output);
		}
		delete atom;
	}
	
	*segment = block_Realloc(*segment, 0, output->GetDataSize());
    if (*segment != NULL)
    {
        memcpy((*segment)->p_buffer, output->GetData(), output->GetDataSize());
    }

	delete file;
	if (input) input->Release();
	if (output) output->Release();
}
