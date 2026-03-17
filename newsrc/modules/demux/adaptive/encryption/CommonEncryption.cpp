/*****************************************************************************
 * CommonEncryption.cpp
 *****************************************************************************
 * Copyright (C) 2015-2019 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "CommonEncryption.hpp"
#include "Ap4.h"
#include "Keyring.hpp"
#include "../SharedResources.hpp"

#include <vlc_common.h>
#include <vlc_block.h>
#include <vlc_strings.h>

#ifdef HAVE_GCRYPT
 #include <gcrypt.h>
 #include <vlc_gcrypt.h>
#endif

using namespace adaptive::encryption;


CommonEncryption::CommonEncryption()
{
    method = CommonEncryption::Method::None;
}

void CommonEncryption::mergeWith(const CommonEncryption &other)
{
    if(method == CommonEncryption::Method::None &&
       other.method != CommonEncryption::Method::None)
        method = other.method;
    if(uri.empty() && !other.uri.empty())
        uri = other.uri;
    if(iv.empty() && !other.iv.empty())
        iv = other.iv;
}

CommonEncryptionSession::CommonEncryptionSession()
{
    ctx = nullptr;
}


CommonEncryptionSession::~CommonEncryptionSession()
{
    close();
}

bool CommonEncryptionSession::start(SharedResources *res, const CommonEncryption &enc)
{
    if(ctx)
        close();
    encryption = enc;
    if(encryption.method == CommonEncryption::Method::AES_128_CTR)
    {
        if (key.empty())
        {
            if(!encryption.uri.empty())
            {
                const std::vector<unsigned char> rawKey = res->getKeyring()->getKey(res, encryption.uri);
                if (rawKey.size() != 16)
                    return false;
                char* hexKey = new char[33];
                vlc_hex_encode_binary(&rawKey[0], rawKey.size(), hexKey);
                const std::string keyString = std::string(hexKey);
                delete[] hexKey;
                key = std::vector<unsigned char>(keyString.begin(), keyString.end());
            }
            else
            {
                const std::string keyString = res->getKeyring()->getCustomKey(std::string(encryption.iv.begin(), encryption.iv.end()));
                key = std::vector<unsigned char>(keyString.begin(), keyString.end());
            }
            if(key.size() != 32)
                return false;
        }
        return true;
    }
#ifndef HAVE_GCRYPT
    /* We don't use the SharedResources */
    VLC_UNUSED(res);
#else
    if(encryption.method == CommonEncryption::Method::AES_128_CBC)
    {
        if(key.empty())
        {
            if(!encryption.uri.empty())
                key = res->getKeyring()->getKey(res, encryption.uri);
            if(key.size() != 16)
                return false;
        }

        vlc_gcrypt_init();
        gcry_cipher_hd_t handle;
        if( gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0) ||
                gcry_cipher_setkey(handle, &key[0], 16) ||
                gcry_cipher_setiv(handle, &encryption.iv[0], 16) )
        {
            gcry_cipher_close(handle);
            ctx = nullptr;
            return false;
        }
        ctx = handle;
    }
#endif
    return true;
}

void CommonEncryptionSession::close()
{
#ifdef HAVE_GCRYPT
    gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(ctx);
    if(ctx)
        gcry_cipher_close(handle);
    ctx = nullptr;
#endif
}

size_t CommonEncryptionSession::decrypt(void *inputdata, size_t inputbytes, bool last)
{
#ifndef HAVE_GCRYPT
    VLC_UNUSED(inputdata);
    VLC_UNUSED(last);
#else
    gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(ctx);
    if(encryption.method == CommonEncryption::Method::AES_128_CBC && ctx)
    {
        if ((inputbytes % 16) != 0 || inputbytes < 16 ||
            gcry_cipher_decrypt(handle, inputdata, inputbytes, nullptr, 0))
        {
            inputbytes = 0;
        }
        else if(last)
        {
            /* last bytes */
            /* remove the PKCS#7 padding from the buffer */
            const uint8_t pad = reinterpret_cast<uint8_t *>(inputdata)[inputbytes - 1];
            for(uint8_t i=0; i<pad && i<16; i++)
            {
                if(reinterpret_cast<uint8_t *>(inputdata)[inputbytes - i - 1] != pad)
                    break;
                if(i+1==pad)
                    inputbytes -= pad;
            }
        }
    }
    else
#endif
    if(encryption.method != CommonEncryption::Method::None)
    {
        inputbytes = 0;
    }

    return inputbytes;
}

void CommonEncryptionSession::decrypt(block_t** fragment)
{
    const std::string keyId(encryption.iv.begin(), encryption.iv.end());
    const std::string keyString(key.begin(), key.end());
    if (keyId.size() != 32 || keyString.size() != 32) {
		return;
	}

	unsigned char keyID[16];
	unsigned char decryptionKey[16];
	AP4_ParseHex(keyId.c_str(), keyID, 16);
	AP4_ParseHex(keyString.c_str(), decryptionKey, 16);

	AP4_ProtectionKeyMap keyMap;
	keyMap.SetKeyForKid(keyID, decryptionKey, 16);

	AP4_MemoryByteStream* inputBuffer = new AP4_MemoryByteStream((*fragment)->p_buffer, (*fragment)->i_buffer);
	AP4_MemoryByteStream* decryptedOutputBuffer = new AP4_MemoryByteStream();
	AP4_CencDecryptingProcessor* processor = new AP4_CencDecryptingProcessor(&keyMap);

	const AP4_Result result = processor->Process(*inputBuffer, *decryptedOutputBuffer);

	delete processor;
	inputBuffer->Release();

	if (AP4_FAILED(result)) {
		decryptedOutputBuffer->Release();
		return;
	}

    *fragment = block_Realloc(*fragment, 0, decryptedOutputBuffer->GetDataSize());
    if (*fragment) {
        memcpy((*fragment)->p_buffer, decryptedOutputBuffer->GetData(), decryptedOutputBuffer->GetDataSize());
    }

	decryptedOutputBuffer->Release();
}

void CommonEncryptionSession::split(block_t** fragment, uint8_t** initData, size_t& initSize)
{
    AP4_Result result;
    unsigned int track_ids[CommonEncryptionSession::AP4_SPLIT_MAX_TRACK_IDS];

	AP4_MemoryByteStream* input = new AP4_MemoryByteStream((*fragment)->p_buffer, (*fragment)->i_buffer);
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
			if (track_id == track_ids[0]) {
				if (output) {
					output->Release();
					output = NULL;
				}

				output = new AP4_MemoryByteStream();
			}
		}

		// write the atom
		if (output && atom->GetType() != AP4_ATOM_TYPE_MFRA) {
			atom->Write(*output);
		}
		delete atom;
	}
	
	*fragment = block_Realloc(*fragment, 0, output->GetDataSize());
    if (*fragment) {
        memcpy((*fragment)->p_buffer, output->GetData(), output->GetDataSize());
    }

	delete file;
	if (input) {
        input->Release();
    }
	if (output) {
        output->Release();
    }
}

void CommonEncryptionSession::split(block_t** fragment)
{
    AP4_Result result;
	unsigned int track_ids[CommonEncryptionSession::AP4_SPLIT_MAX_TRACK_IDS];

	AP4_MemoryByteStream* input = new AP4_MemoryByteStream((*fragment)->p_buffer, (*fragment)->i_buffer);
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
			if (track_id == track_ids[0]) {
				if (output) {
					output->Release();
					output = NULL;
				}

				output = new AP4_MemoryByteStream();
			}
		}

		// write the atom
		if (output && atom->GetType() != AP4_ATOM_TYPE_MFRA) {
			atom->Write(*output);
		}
		delete atom;
	}
	
	*fragment = block_Realloc(*fragment, 0, output->GetDataSize());
    if (*fragment) {
        memcpy((*fragment)->p_buffer, output->GetData(), output->GetDataSize());
    }

	delete file;
	if (input) {
        input->Release();
    }
	if (output) {
        output->Release();
    }
}
