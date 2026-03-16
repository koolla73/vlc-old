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
#include "Ap4Decrypt.hpp"
#include "Keyring.hpp"
#include "../SharedResources.hpp"

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

void CommonEncryptionSession::decrypt(block_t** segment, bool last)
{
#ifndef HAVE_GCRYPT
    VLC_UNUSED(segment);
    VLC_UNUSED(last);
#else
    gcry_cipher_hd_t handle = reinterpret_cast<gcry_cipher_hd_t>(ctx);
    if(encryption.method == CommonEncryption::Method::AES_128_CBC && ctx)
    {
        if (((*segment)->i_buffer % 16) != 0 || (*segment)->i_buffer < 16 ||
            gcry_cipher_decrypt(handle, reinterpret_cast<void*>((*segment)->p_buffer), (*segment)->i_buffer, nullptr, 0))
        {
            (*segment)->i_buffer = 0;
        }
        else if(last)
        {
            /* last bytes */
            /* remove the PKCS#7 padding from the buffer */
            const uint8_t pad = (*segment)->p_buffer[(*segment)->i_buffer - 1];
            for(uint8_t i=0; i<pad && i<16; i++)
            {
                if((*segment)->p_buffer[(*segment)->i_buffer - i - 1] != pad)
                    break;
                if(i+1==pad)
                    (*segment)->i_buffer -= pad;
            }
        }
    }
    else
#endif
    if(encryption.method == CommonEncryption::Method::AES_128_CTR)
    {
        const std::string kid(encryption.iv.begin(), encryption.iv.end());
        const std::string keyString(key.begin(), key.end());
        AP4_Decrypt::decrypt(segment, kid.c_str(), keyString.c_str());
        
        AP4_Decrypt::split(segment);
    }
    else if(encryption.method != CommonEncryption::Method::None)
    {
        (*segment)->i_buffer = 0;
    }
}
