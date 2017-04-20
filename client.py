"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
import crypto
import util

import numpy as np


def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        encrypt_iv = self.storage_server.get(self.username + "IV")
        sign_iv = self.storage_server.get(self.username + "Sign_IV")
        encrypt_iv_mac = self.storage_server.get(self.username + "MAC")
        sign_iv_mac = self.storage_server.get(self.username + "Sign_MAC")

        self.encryption_ivs = {}
        # Check if metadata has already been created
        if encrypt_iv is None and sign_iv is None and encrypt_iv_mac is None and sign_iv_mac is None:
            iv = self.crypto.get_random_bytes(32)
            iv_mac = self.crypto.get_random_bytes(32)
            encrypt_iv = self.crypto.asymmetric_encrypt(iv, self.private_key)
            encrypt_iv_mac = self.crypto.asymmetric_encrypt(iv_mac, self.private_key)
            self.storage_server.put(self.username + "IV", encrypt_iv)
            self.storage_server.put(self.username + "MAC", encrypt_iv_mac)
            sign_iv = self.crypto.asymmetric_sign(encrypt_iv, self.private_key)
            sign_iv_mac = self.crypto.asymmetric_sign(encrypt_iv_mac, self.private_key)
            self.storage_server.put(self.username + "Sign_IV", sign_iv)
            self.storage_server.put(self.username + "Sign_MAC", sign_iv_mac)

        if self.crypto.asymmetric_verify(encrypt_iv, sign_iv, self.private_key) and self.crypto.asymmetric_verify(
                encrypt_iv_mac, sign_iv_mac, self.private_key):
            self.iv = self.crypto.asymmetric_decrypt(encrypt_iv, self.private_key)
            self.iv_mac = self.crypto.asymmetric_decrypt(encrypt_iv_mac, self.private_key)
        else:
            raise IntegrityError

    class node(object):
        pointer, encryption, mac_keys = None, None, None

        def __init__(self, pointer, encryption, mac_keys):
            self.pointer = pointer
            self.encryption = encryption
            self.mac_keys = mac_keys

        def to_json_obj(self):
            return self.pointer, self.encryption, self.mac_keys, "node"

    class merkle_node(object):
        left_child, right_child, encryption, mac_keys, data_pointer = None, None, None, None, None

        def __init__(self, left_child, right_child, data_pointer, length, crypto_hash):
            self.left_child = left_child
            self.right_child = right_child
            self.data_pointer = data_pointer
            self.length = length
            self.crypto_hash = crypto_hash

        def to_json_obj(self):
            return self.left_child, self.right_child, self.data_pointer, self.length, self.crypto_hash, "merkle-node"

    def upload(self, name, value):
        'NEW STUFF'
        encrypt_name = self.crypto.symmetric_encrypt(
            self.crypto.cryptographic_hash(path_join(self.username, name), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
        # Try to read the key_node
        key_node, file_iv = self.fetch_and_decrypt(encrypt_name, self.iv, self.iv_mac)
        'NEW STUFF'
        # If failed to read key_node and file_iv, this is a new file
        if key_node is None and file_iv is None:
            # Create and store key_node, data_node, and data
            'NEW STUFF'
            key_encryption = self.crypto.get_random_bytes(32)
            key_auth = self.crypto.get_random_bytes(32)
            data_iv = self.crypto.get_random_bytes(16)
            data_node_iv = self.crypto.get_random_bytes(16)
            key_node_iv = self.crypto.get_random_bytes(16)
            # Need to store them backwards. First store data then data_node then key_node
            ###print('before storeing as a merkel tree')

            'Need to store the file as a Merkel Tree.'
            # Calculate the chunk size. 
            total_num_bytes = len(value)
            chunk_size = int(np.log2(total_num_bytes))
            if chunk_size == 0:
                chunk_size = 1
            values = self.return_values(total_num_bytes, chunk_size, value)
            self.encryption_ivs[name] = []
            #print(values)
            i, new_values = self.i_new_values(values, name, key_encryption, key_auth, False)

            data_name = self.merkle_create_and_store(new_values, self.username, name, key_encryption, key_auth, i)

            data_node_name = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data_node", 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
            data_node = self.node(data_name, key_encryption, key_auth)
            self.encrypt_and_put(data_node, data_node_name, key_encryption, key_auth, data_node_iv)
            key_node = self.node(data_node_name, key_encryption, key_auth)
            self.encrypt_and_put(key_node, encrypt_name, self.iv, self.iv_mac, key_node_iv)

            # Create user_list for file and upload to server.
            user_list = []
            userlist_iv = self.crypto.get_random_bytes(16)
            user_list_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "User_lists", "SHA"), self.iv, 'AES','CBC', IV=None)
            self.encrypt_and_put(user_list, user_list_id, self.iv, self.iv_mac, userlist_iv)

            'NEW STUFF'
            return True
        # Otherwise the key node exists and we are updating
        # Read data_node and data and update data
        
        ###print(values)
        data_node, data_iv = self.fetch_and_decrypt(key_node.pointer, key_node.encryption, key_node.mac_keys)
        tmp_data_node, tmp_data_iv = data_node, data_iv
        while isinstance(tmp_data_node, self.node):
            data_node, data_iv = tmp_data_node, tmp_data_iv
            tmp_data_node, tmp_data_iv = self.fetch_and_decrypt(tmp_data_node.pointer, tmp_data_node.encryption, tmp_data_node.mac_keys)

        'Need to update the file as a Merkel Tree.'
        # Store value in data_node.pointer
        new_iv = self.crypto.get_random_bytes(16)
        'sean_merkle_tree'
        ###print(values)
        total_num_bytes = len(value)
        chunk_size = int(np.log2(total_num_bytes))
        if chunk_size == 0:
            chunk_size = 1
        values = self.return_values(total_num_bytes, chunk_size, value)
        self.client_dictionary = {}
        #print(values)
        i, values = self.i_new_values(values, name, key_node.encryption, key_node.mac_keys, True)
        ##print("\t\t OTHER-TREE")
        #for value in values:
        #    #print(value.crypto_hash[0:5])
        client_tree = self.create_client_tree(values, self.username, name, data_node.encryption, data_node.mac_keys, i)
        ##print("client_tree" + str(client_tree.data_pointer))
        ##print("UPDATE-MERKLE")
        # if tmp_data_node.length != client_tree.length:
        #     ##print("inside")
        #     t_d_node = key_node
        #     # cnt = 0
        #     while isinstance(t_d_node, self.node):
        #         # cnt = cnt + 1
        #         # #print(cnt)
        #         before_node = key_node
        #         key_node = t_d_node
        #         t_d_node, t_d_iv = self.fetch_and_decrypt(t_d_node.pointer, t_d_node.encryption, t_d_node.mac_keys)
        #     # 
        #     ##print(before_node.pointer + " pointer 1")
        #     ##print("\t" + key_node.pointer + " pointer 2")
        #     ##print("\t" + t_d_node.pointer + " pointer 3")
        #     data_node.pointer = self.merkle_create_and_store(values, self.username, name, key_node.encryption, key_node.mac_keys, i)
        #     new_data_node_iv = self.crypto.get_random_bytes(16)
        #     self.encrypt_and_put(data_node, before_node.pointer, self.iv, self.iv_mac, new_data_node_iv)
        # else:
        self.update_merkle_tree(name, tmp_data_node, client_tree, data_node.encryption, data_node.mac_keys, data_node.pointer)
                         # update_merkle_tree(self, name, server_tree, client_tree, key_encryption, key_auth):
        'sean_merkle_tree'
        # self.encrypt_and_put(value, data_node.pointer, data_node.encryption, data_node.mac_keys, new_iv)
        'Need to store the file as a Merkel Tree.'

        return True
    def i_new_values(self, values, name, key_encryption, key_auth, create_dict):
        ###print('after first for loop')
        i = 1 
        new_values = []
        ##print(values)
        for chunk in values:
            # Create id and put chunk.
            value_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data" + str(i), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
         
            chunk_iv = self.crypto.get_random_bytes(16)
            'Need to Store these ivs'
            'Need to Store these ivs'
            if create_dict:
                chunk_iv = self.encryption_ivs[name][i-1]
                ##print(self.encryption_ivs[name])
                ##print("\t\t INSIDE")
                ##print(self.encryption_ivs[name][i-1])
                self.encrypt_merkle(chunk, key_encryption, key_auth, chunk_iv)
                self.client_dictionary[value_id] = chunk
                ##print(chunk_hash)
            else:
                ##print("First")
                self.encryption_ivs[name].append(chunk_iv) 
                self.encrypt_and_put(chunk, value_id, key_encryption, key_auth, chunk_iv) 
                ##print(chunk_hash)
            # Create merkel node.
            chunk_hash = self.crypto.cryptographic_hash(chunk, 'SHA256')
            merkel_node = self.merkle_node(None, None, value_id, len(chunk), chunk_hash)
            #print(chunk + "\t\t" + chunk_hash[0:5])
            new_values.append(merkel_node)
            i = i + 1
        return i, new_values
         
 
    def return_values(self, total_num_bytes, chunk_size, value):
        values = []
        num_of_blocks = int(total_num_bytes/chunk_size)
        num_bytes = 0
        while num_bytes < total_num_bytes:
        #for i in range(0, num_of_blocks):
                ###print(i)
                # check how to get each block.
            if num_bytes + chunk_size > total_num_bytes:
                tmp = value[num_bytes:]
            else:
                tmp = value[num_bytes: num_bytes + chunk_size]
            num_bytes += chunk_size
            values.append(tmp)        
        return values   
        # return False

    def merkle_create_and_store(self, values, username, name, key_encryption, key_auth, i):
        'Create and store a merkle  tree out of values'
        # Assume values is array of tuples.
        new_pairs = []
        tmp = []
        #for pair in values:
        #for j in range(0, len(values) - 1):
        j = 0
        len_values = len(values)
        ##print("\t\t\t\t VALUES")
        ##print(values)
        if len_values == 1:
            data1_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data" + str(i), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
            data1_iv = self.crypto.get_random_bytes(16)
            encrypted1 = self.encrypt_and_put(values[0], data1_id, key_encryption, key_auth, data1_iv)
            return data1_id
             
        while j < (len(values)):
            # Need to encrypt_and_put
            # def encrypt_and_put(self, data, data_id, key_encryption, key_auth, data_iv):
            # data_name = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data" + str(num_bytes_stored), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)

            data1_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data" + str(i), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
            i = i + 1
            data2_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data" + str(i), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
            i = i + 1
            data1_iv = self.crypto.get_random_bytes(16)
            data2_iv = self.crypto.get_random_bytes(16)
            self.encrypt_and_put(values[j], data1_id, key_encryption, key_auth, data1_iv)
            encrypted1 = values[j].crypto_hash
            ##print("\t\t\t\t\t\t\t LEN_VALUES")
            ##print(len(values))
            ##print ("\t\t j:   " + str(j))
            if ((j + 1) == len(values)):
                #j = j + 1 
                ##print("\t\t\t j:   " + str(j))
                new_pairs.append(values[j])
                j = j + 1
                continue
            self.encrypt_and_put(values[j+1], data2_id, key_encryption, key_auth, data2_iv)
            encrypted2 = values[j+1].crypto_hash
            # Now I need to hash the two together.
            hash_value = self.crypto.cryptographic_hash(encrypted1 + encrypted2, 'SHA256')
            'making merkle nodes'
            server_tree = self.merkle_node(data1_id, data2_id, None, values[j].length + values[j+1].length, hash_value)
            j = j + 2
            'making merkle nodes'
            new_pairs.append(server_tree)
#            tmp.append(hash_value)
#            # Every two iterations append to new_pairs
#            if i % 2 == 0:
#                new_pairs.append(tmp)
#                tmp = []

        ##print("\t NEW-PAIRS")
        ##print(new_pairs)
        return self.merkle_create_and_store(new_pairs, username, name, key_encryption, key_auth, i)

    def update_merkle_tree(self, name, server_tree, client_tree, key_encryption, key_auth, curr_ptr, layer=0):
        # hash the root to compare it with the hash of the new file.
        ##print("\t\t\t ROOT-HASH")
        ##print(server_tree)
        ##print(client_tree)
        root_hash = server_tree.crypto_hash
        client_root_hash = client_tree.crypto_hash
        ##print(("\t\t" * layer) + str(layer) + "   " + root_hash[:5] + "    " + client_root_hash[:5])

        # root is the root of the merkle  tree.
        if client_root_hash != root_hash:
            # split the file into two pieces according to the lengths of the subtree stored on the server.
            if server_tree.data_pointer is not None:
                # if left_tree or right_tree is a leaf. Since the left and right have same length, only need to check one.
                #server_tree.crypto_hash = client_tree.crypto_hash
                ##print(client_tree.data_pointer)
                client_data = self.client_dictionary[client_tree.data_pointer]
                ##print("\t\t\t CLIENT-DATA")
                ##print(client_data)
                new_data_iv = self.crypto.get_random_bytes(16)
                self.encrypt_and_put(client_data, server_tree.data_pointer, key_encryption, key_auth, new_data_iv)
                new_node_iv = self.crypto.get_random_bytes(16)
                client_tree = self.merkle_node(None, None, server_tree.data_pointer, client_tree.length, client_root_hash)
                self.encrypt_and_put(client_tree, curr_ptr, key_encryption, key_auth, new_node_iv)



            else:
                #client_left_tree = client_tree.left_child

                #client_right_tree = client_tree.right_child

                server_left_tree_id = server_tree.left_child
                ##print(server_left_tree_id)
                server_left_node, iv = self.fetch_and_decrypt(server_left_tree_id, key_encryption, key_auth)
                client_left_tree = self.client_dictionary[client_tree.left_child]

                server_right_tree_id = server_tree.right_child
                server_right_node, iv = self.fetch_and_decrypt(server_right_tree_id, key_encryption, key_auth)
                client_right_tree = self.client_dictionary[client_tree.right_child]

                self.update_merkle_tree(name, server_left_node, client_left_tree, key_encryption, key_auth,server_left_tree_id, layer + 1)
                self.update_merkle_tree(name, server_right_node, client_right_tree, key_encryption, key_auth, server_right_tree_id, layer + 1)
                new_node_iv = self.crypto.get_random_bytes(16)
                client_tree = self.merkle_node(server_left_tree_id, server_right_tree_id, client_tree.data_pointer, client_tree.length, client_root_hash)
                self.encrypt_and_put(client_tree, curr_ptr, key_encryption, key_auth, new_node_iv)

    def create_client_tree(self, values, username, name, key_encryption, key_auth, i):
        # Assume values is array of tuples.
        new_pairs = []
        tmp = []
        #for pair in values:
        #for j in range(0, len(values) - 1):
        j = 0
        len_values = len(values)
        ##print("\t\t\t\t VALUES")
        ##print(values)
        if len_values == 1:
            #data1_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data" + str(i), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
            #data1_iv = self.crypto.get_random_bytes(16)
            #encrypted1 = self.encrypt_and_put(values[0], data1_id, key_encryption, key_auth, data1_iv)
            #self.client_dictionary.update({data1_id, 
            #encrypted1 = self.encrypt_merkle(values[0], key_encryption, key_auth, data1_iv)
            return values[0] 
             
        while j < (len(values)):
            # Need to encrypt_and_put
            # def encrypt_and_put(self, data, data_id, key_encryption, key_auth, data_iv):
            # data_name = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data" + str(num_bytes_stored), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)

            data1_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data" + str(i), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
            i = i + 1
            data2_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name) + "Data" + str(i), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
            i = i + 1
            data1_iv = self.crypto.get_random_bytes(16)
            data2_iv = self.crypto.get_random_bytes(16)
            self.encrypt_merkle(values[j], key_encryption, key_auth, data1_iv)
            encrypted1 = values[j].crypto_hash
            ##print("\t\t\t\t\t\t\t LEN_VALUES")
            ##print(len(values))
            ##print ("\t\t j:   " + str(j))
            if (j + 1) == len(values):
                #j = j + 1 
                ##print("\t\t\t j:   " + str(j))
                new_pairs.append(values[j])
                j = j + 1
                continue
            self.encrypt_merkle(values[j+1], key_encryption, key_auth, data2_iv)
            encrypted2 = values[j+1].crypto_hash
            # Now I need to hash the two together.
            hash_value = self.crypto.cryptographic_hash(encrypted1 + encrypted2, 'SHA256')
            'making merkle nodes'
            self.client_dictionary[data1_id] = values[j]
            self.client_dictionary[data2_id] = values[j+1]
            server_tree = self.merkle_node(data1_id, data2_id, None, values[j].length + values[j+1].length, hash_value)
            ##print(server_tree)
            j = j + 2
            'making merkle nodes'
            new_pairs.append(server_tree)
#            tmp.append(hash_value)
#            # Every two iterations append to new_pairs
#            if i % 2 == 0:
#                new_pairs.append(tmp)
#                tmp = []

        ##print("\t NEW-PAIRS")
        ##print(new_pairs)
        return self.create_client_tree(new_pairs, username, name, key_encryption, key_auth, i)


    def download_merkle_tree(self, name, server_tree, key_encryption, key_auth):
        ###print(server_tree.data_pointer)
        if server_tree.data_pointer is not None:
            
            data, data_iv = self.fetch_and_decrypt(server_tree.data_pointer, key_encryption, key_auth)
            ##print("\t\t\t DATA")
            ##print(data)
            return data;
        else:

            ##print("HELLO WORLD")
            server_left_tree_id = server_tree.left_child
            server_left_node, iv = self.fetch_and_decrypt(server_left_tree_id, key_encryption, key_auth)

            server_right_tree_id = server_tree.right_child
            server_right_node, iv = self.fetch_and_decrypt(server_right_tree_id, key_encryption, key_auth)

            return self.download_merkle_tree(name, server_left_node, key_encryption, key_auth) \
                   + self.download_merkle_tree(name, server_right_node, key_encryption, key_auth)

    def download(self, name):
        try:
            encrypt_name = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, name), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
    
            # Fetch key_node
            'NEW STUFF'
            key_node, file_iv = self.fetch_and_decrypt(encrypt_name, self.iv, self.iv_mac)
            if key_node is None:
                return key_node
            data_node, data_iv = self.fetch_and_decrypt(key_node.pointer, key_node.encryption, key_node.mac_keys)
            # Iterate until we hit the data
            root_node = key_node
            while isinstance(data_node, self.node):
                root_node = data_node
                data_node, data_iv = self.fetch_and_decrypt(data_node.pointer, data_node.encryption, data_node.mac_keys)
                if data_node is None:
                    return data_node
            # Return the data

            'merkle stuff'
            ###print(isinstance(data_node, self.merkle_node))
            ###print(root_key)
            out = self.download_merkle_tree(name, data_node, root_node.encryption, root_node.mac_keys)
            ##print("\t\t OUT")
            ##print(out)
            return out
            'merkle stuff'
           # return data_node
        except:
            raise IntegrityError
    
    
    def share(self, share_user, filename):
        # ##print('atakkjckjdkjf')
        encrypt_filename = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, filename), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
        key_node, file_iv = self.fetch_and_decrypt(encrypt_filename, self.iv, self.iv_mac)
        # ##print('middle')
        if key_node is None:
            return key_node
        # Get public key of user to encrypt message to send.
        share_user_public_key = self.pks.get_public_key(share_user)
        # ##print('middle')
        nonce = self.crypto.get_random_bytes(0)
        encrypt_key = self.crypto.get_random_bytes(16)
        mac_keys = self.crypto.get_random_bytes(16)
        share_iv = self.crypto.get_random_bytes(16)
        # ##print('middle')
        share_node = self.node(key_node.pointer, key_node.encryption, key_node.mac_keys)
        # This is the pointer to the share node
        share_node_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(share_user, filename) + "Share", 'SHA'), self.iv, 'AES', 'CBC', IV=None)
        # ##print(share_node_id)
        # ##print(share_user)
        #        if (share_user == 'eve'):
        #            ##print(filename, self.iv)
        # ##print(' break')
        self.encrypt_and_put(share_node, share_node_id, encrypt_key, mac_keys, share_iv)
        # Fetch user_list.
        # ##print(self.username + filename)
    
        user_list_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, filename) + "User_lists", "SHA"), self.iv, 'AES', 'CBC', IV=None)
        user_list, userlist_iv = self.fetch_and_decrypt(user_list_id, self.iv, self.iv_mac)
        # ##print(user_list)
        user_list.append((share_user, encrypt_key, mac_keys))
        # Put user_list
        self.encrypt_and_put(user_list, user_list_id, self.iv, self.iv_mac, userlist_iv)
        # Send message
        message = util.to_json_string([encrypt_key, mac_keys, share_node_id, nonce])
        encrypt_message = self.crypto.asymmetric_encrypt(message, share_user_public_key)
        sign_encrypt_message = self.crypto.asymmetric_sign(encrypt_message, self.private_key)
        # ##print(encrypt_message)
        # ##print(sign_encrypt_message)
        return util.to_json_string([sign_encrypt_message, encrypt_message])
    
    
    def receive_share(self, from_username, newname, message):
        (sign_encrypt_message, encrypt_message) = util.from_json_string(message)
        user_public_key = self.pks.get_public_key(from_username)
    
        right_sign = self.crypto.asymmetric_verify(encrypt_message, sign_encrypt_message, user_public_key)
        if not right_sign:
            raise IntegrityError
            # Message_from is [encrypt_key, mac_keys, share_node_keys, nonce]
        message_from = self.crypto.asymmetric_decrypt(encrypt_message, self.private_key)
        message_from = util.from_json_string(message_from)
        key_node = self.node(message_from[2], message_from[0], message_from[1])
        # store the key_node in the server.\

        'Need to grab ivs for this file'
        share_node, share_iv = self.fetch_and_decrypt(message_from[2], message_from[0], message_from[1])
        # Recreate merkle tree
        data_node = share_node
        root_node = share_node
        while isinstance(data_node, self.node):
           root_node = data_node
           data_node, data_iv = self.fetch_and_decrypt(data_node.pointer, data_node.encryption, data_node.mac_keys)
           #if data_node is None:
           #    return data_node
        #self.merkle_tree = data_node
        #self.client_dictionary[newname] = {}
        self.encryption_ivs[newname] = []
        self.reconstruct_merkle(data_node, root_node.encryption, root_node.mac_keys, newname) 
 
        'Need to grab ivs for this file'

        key_node_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, newname), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
        file_iv = self.crypto.get_random_bytes(16)
        self.encrypt_and_put(key_node, key_node_id, self.iv, self.iv_mac, file_iv)
        # Create user_list for file and upload to server.
        user_list = []
        userlist_iv = self.crypto.get_random_bytes(16)
        user_list_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, newname) + "User_lists", "SHA"), self.iv, 'AES', 'CBC', IV=None)
        self.encrypt_and_put(user_list, user_list_id, self.iv, self.iv_mac, userlist_iv)
    
    def reconstruct_merkle(self, merkle_node, key_encryption, key_auth, filename):
        'Reconstruct merkle tree'
        if merkle_node.data_pointer is not None:
            data_chunk, data_chunk_iv = self.fetch_and_decrypt(merkle_node.data_pointer, key_encryption, key_auth)
            'Store the IVs'
            self.encryption_ivs[filename].append(data_chunk_iv)
            'Store the IVs'
            #self.client_dictionary[filename][merkle_node.data_pointer] = data_chunk
        else:
            server_left_tree_id = merkle_node.left_child
            server_left_node, iv = self.fetch_and_decrypt(server_left_tree_id, key_encryption, key_auth)
            #self.client_dictionary[filename][server_left_tree_id] = server_left_node
            server_right_tree_id = merkle_node.right_child
            server_right_node, iv = self.fetch_and_decrypt(server_right_tree_id, key_encryption, key_auth)
            #self.client_dictionary[filename][server_right_tree_id] = server_right_node
             

            self.reconstruct_merkle(server_left_node, key_encryption, key_auth, filename) 
            self.reconstruct_merkle(server_right_node, key_encryption, key_auth, filename) 
 
    
    def revoke(self, user, filename):
        encrypt_filename = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, filename), 'SHA256'), self.iv, 'AES', 'CBC', IV=None)
        # Fetch encrypt_filename
        key_node, file_iv = self.fetch_and_decrypt(encrypt_filename, self.iv, self.iv_mac)
    
        # Fetch key_node.pointer
        data_node, data_node_iv = self.fetch_and_decrypt(key_node.pointer, key_node.encryption, key_node.mac_keys)
    
        # Fetch data_node.pointer
        data, data_iv = self.fetch_and_decrypt(data_node.pointer, data_node.encryption, data_node.mac_keys)
    
        ######################### Backward pass
        # Generate new keys for encryption and authentication
        new_key_encryption = self.crypto.get_random_bytes(16)
        new_key_auth = self.crypto.get_random_bytes(16)
    
        new_data_iv = self.crypto.get_random_bytes(16)
        # Re-encrypt the data.
        #self.encrypt_and_put(data, data_node.pointer, new_key_encryption, new_key_auth, new_data_iv)  ####
        # Re-encrypt the data.
        'Need to re-encrypt the whole merkle_tree'
        value = self.download_merkle_tree(filename, data, data_node.encryption, data_node.mac_keys)
        total_num_bytes = len(value)
        chunk_size = int(np.log2(total_num_bytes))
        if chunk_size == 0:
            chunk_size = 1 
        values = self.return_values(total_num_bytes, chunk_size, value)
        i, new_values = self.i_new_values(values, filename, new_key_encryption, new_key_auth, False)
        data_name = self.merkle_create_and_store(new_values, self.username, filename, new_key_encryption, new_key_auth, i)
        data_node.pointer = data_name
        'Need to re-encrypt the whole merkle_tree'


        new_data_node_iv = self.crypto.get_random_bytes(16)
        # Re-encrypt the data_node
        data_node.encryption, data_node.mac_keys = new_key_encryption, new_key_auth
        self.encrypt_and_put(data_node, key_node.pointer, new_key_encryption, new_key_auth, new_data_node_iv)  ###
    
        # Re-encrypt the key_node
        key_node.encryption, key_node.mac_keys = new_key_encryption, new_key_auth
    
        new_file_iv = self.crypto.get_random_bytes(16)
        self.encrypt_and_put(key_node, encrypt_filename, self.iv, self.iv_mac, new_file_iv)
    
        # GIVE ACCESS BACK TO CHILDREN THAT ARE NOT USER
        user_list_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(self.username, filename) + "User_lists", "SHA"), self.iv, 'AES', 'CBC', IV=None)
        user_list, userlist_iv = self.fetch_and_decrypt(user_list_id, self.iv, self.iv_mac)
        tmp = None
        for child in user_list:
            # ##print(child)
            # Child composed of (user, key_encryption, key_auth)
            if child[0] == user:
                # Skip revoked user
                tmp = child
                continue
                # For each child update their share_node
            #                ##print(filename, self.iv)
            share_node_id = self.crypto.symmetric_encrypt(self.crypto.cryptographic_hash(path_join(child[0], filename) + "Share", 'SHA'), self.iv, 'AES', 'CBC', IV=None)
            # ##print(share_node_id)
            share_node, share_iv = self.fetch_and_decrypt(share_node_id, child[1], child[2])
    
            share_node.encryption, share_node.mac_keys = new_key_encryption, new_key_auth
    
            new_share_iv = self.crypto.get_random_bytes(16)
            self.encrypt_and_put(share_node, share_node_id, child[1], child[2], new_share_iv)
        user_list.remove(tmp)
    
    
    def fetch_and_decrypt(self, encrypted_id, key_encrypt, key_auth):
        string_data = self.storage_server.get(encrypted_id)
        ##print(string_data)
        if string_data is None:
            return None, None
        try:
            encrypt_node, sign_encrypt_node, file_iv = util.from_json_string(string_data)
        except ValueError:
            raise IntegrityError
        # Check encrypt_key_node signature
        string_encrypt_node = util.to_json_string([encrypt_node, file_iv])
        new_auth_encrypt_node = self.crypto.message_authentication_code(string_encrypt_node, key_auth, 'SHA512')
        if new_auth_encrypt_node != sign_encrypt_node:
            raise IntegrityError
            # Decrypt encrypt_key_node
        json_data = self.crypto.symmetric_decrypt(encrypt_node, key_encrypt, 'AES', 'CBC', IV=file_iv)
        data = util.from_json_string(json_data)
        if len(data) == 4 and data[3] == "node":
            data = self.node(data[0], data[1], data[2])
        elif len(data) == 6 and data[5] == "merkle-node":
            data = self.merkle_node(data[0], data[1], data[2], data[3], data[4])
        return data, file_iv
    
    
    def encrypt_and_put(self, data, data_id, key_encryption, key_auth, data_iv):
        # Re-encrypt the data.
        if isinstance(data, self.node):
            data = data.to_json_obj()
        elif isinstance(data, self.merkle_node):
            data = data.to_json_obj()
        json_data = util.to_json_string(data)
        new_encrypt_data = self.crypto.symmetric_encrypt(json_data, key_encryption, 'AES', 'CBC', IV=data_iv)
    
        string_new_encrypt_data = util.to_json_string([new_encrypt_data, data_iv])
        sign_new_encrypt_data = self.crypto.message_authentication_code(string_new_encrypt_data, key_auth, 'SHA512')
        # Put new_encrypt_data back in server
        string_data = util.to_json_string((new_encrypt_data, sign_new_encrypt_data, data_iv))
        self.storage_server.put(data_id, string_data)
        # 'MERKEL TREE'
        self.crypto.cryptographic_hash(string_data, 'SHA256')
        return  self.crypto.cryptographic_hash(string_data, 'SHA256')
        # 'MERKEL TREE'
    
    
    def encrypt_merkle(self, data, key_encryption, key_auth, data_iv):
        # Re-encrypt the data.
        if isinstance(data, self.node):
            data = data.to_json_obj()
        elif isinstance(data, self.merkle_node):
            data = data.to_json_obj()
        json_data = util.to_json_string(data)
        new_encrypt_data = self.crypto.symmetric_encrypt(json_data, key_encryption, 'AES', 'CBC', IV=data_iv)
    
        string_new_encrypt_data = util.to_json_string([new_encrypt_data, data_iv])
        sign_new_encrypt_data = self.crypto.message_authentication_code(string_new_encrypt_data, key_auth, 'SHA512')
        # Put new_encrypt_data back in server
        string_data = util.to_json_string((new_encrypt_data, sign_new_encrypt_data, data_iv))
#        self.storage_server.put(data_id, string_data)
        # 'MERKEL TREE'
        self.crypto.cryptographic_hash(string_data, 'SHA256')
        return  self.crypto.cryptographic_hash(string_data, 'SHA256')
        # 'MERKEL TREE'
 
