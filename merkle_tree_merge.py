#!/usr/bin/python3
import hashlib
import math
import queue
import time
#from sha3 import keccak_256

def hash_leaf(leaf_value):
    '''Convert a leaf value to a digest'''
    #assert(leaf_value < 2**256)
    #return leaf_value.to_bytes(32, 'big')
    hash = hashlib.sha256()
    hash.update(bytes(leaf_value,encoding='utf-8'))
    leaf=hash.hexdigest()
    return leaf

def hash_node(left_hash, right_hash):
    '''Convert two digests to their Merkle node's digest'''
    mRoot = hashlib.sha256(bytearray.fromhex(left_hash) + bytearray.fromhex(right_hash)).hexdigest()
    return mRoot
    #return keccak_256(left_hash + right_hash).digest()

def make_tree(leafs):
    '''Compute the Merkle tree of a list of values.
    The result is returned as a list where each value represents one hash in the
    tree. The indices in the array are as in a bbinary heap array.
    '''
    start = time.time()
    num_leafs = len(leafs)
    depth = int(math.log2(num_leafs))
    #assert(num_leafs == 2**depth)
    num_nodes = 2 * num_leafs
    tree = [None] * num_nodes
    for i in range(num_leafs):
        tree[2**depth + i] = hash_leaf(leafs[i])
        #print(hash_leaf(leafs[i]))
    for i in range(2**depth - 1, 0, -1):
        tree[i] = hash_node(tree[2*i], tree[2*i + 1])
    end = time.time()
    print ("Make_Tree_Time: "+str(end-start)+"s")
    return tree

def root(tree):
    return tree[1]

def proof(tree, indices):
    '''Given a Merkle tree and a set of indices, provide a list of decommitments
    required to reconstruct the merkle root.'''
    depth = int(math.log2(len(tree))) - 1
    num_leafs = 2**depth
    num_nodes = 2*num_leafs
    #known = [False] * num_nodes
    known = [False] * len(tree)
    #decommitment = []
    decommitment = queue.Queue(maxsize=0)

    for i in indices:    
        known[2**depth + i] = True
    for i in range(2**depth - 1, 0, -1):
        left = known[2*i]
        right = known[2*i + 1]
        if left and not right:
            #decommitment += [tree[2*i + 1]]
            decommitment.put(tree[2*i + 1])
            #print(str(2*i + 1) +":"+ str(tree[2*i + 1]))
        if not left and right:
            #decommitment += [tree[2*i]]
            decommitment.put(tree[2*i])
            #print(str(2*i) +":"+ str(tree[2*i]))
        known[i] = left or right
    print('Decommitment Get Successfly..........')
    return decommitment

def verify(root, depth, values, decommitment, debug_print=False):
    '''Verify a set of leafs in the Merkle tree.
    
    Parameters
    ------------------------
    root
        Merkle root that is commited to.
    depth
        Depth of the Merkle tree. Equal to log2(number of leafs)
    values
        Mapping leaf index => value of the values we want to decommit.
    decommitments
        List of intermediate values required for deconstruction.
    '''
    
    # Create a list of pairs [(tree_index, leaf_hash)] with tree_index decreasing
    queue = []
    #Q = queue.Queue(maxsize=0)
    for index in sorted(values.keys(), reverse=True):
        tree_index = 2**depth + index
        hashleaf = hash_leaf(values[index])
        queue += [(tree_index, hashleaf)]
        #print((tree_index, hash))
        #Q.put((tree_index, hashleaf))
    count = 0
    while True:
        #assert(len(queue) >= 1)

        # Take the top from the queue
        (index, hash) = queue.pop(0)
        #queue = queue[1:]
        #(index, hash) = Q.get()
        if debug_print:
            print(index, hash)

        # The merkle root has tree index 1
        if index == 1:
            return hash == root
            
        # Even nodes get merged with a decommitment hash on the right
        elif index % 2 == 0:
            print("Even")
            #queue += [(index // 2, hash_node(hash, decommitment[0]))]
            #decommitment = decommitment[1:]
            queue += [(index // 2, hash_node(hash,decommitment.get()))]
            #Q.put((index // 2, hash_node(hash, decommitment.get())))
        # Odd nodes can get merged with their neighbour
        elif len(queue) > 0 and queue[0][0] == index - 1:
                # Take the sibbling node from the stack
                (_, sibbling_hash) = queue.pop(0)
                #queue = queue[1:]
                print("Odd Neighbour")
                # Merge the two nodes
                queue += [(index // 2, hash_node(sibbling_hash,hash))]
                #Q.put((index // 2, hash_node(sibbling_hash, hash)))
        # Remaining odd nodes are merged with a decommitment on the left
        else:
            print("Odd")
            # Merge with a decommitment hash on the left
            #queue += [(index // 2, hash_node(decommitment[0], hash))]
            #decommitment = decommitment[1:]
            queue += [(index // 2, hash_node(decommitment.get(), hash))]
            #Q.put((index // 2, hash_node(decommitment.get(), hash)))
        #count = count + 1
        #print(count)
def main():
    f = open('Page','r')
    line = f.read().strip()
    linestr = line.split("\n")
    f.close()
    print('MerkleTree Prepare..........')
    tree = make_tree(linestr)
    Root = root(tree)
    print('MerkleTree root: '+Root)
    pageindex = []
    table={}
    #content = ''.join(sorted(open('page_number_sql1.log'), key=lambda s: int(s.split(" ")[1]),reverse=1))
    #print(content)
    #ft = open('page_number_sql1.log','w')
    #ft.write(content)
    #ft.close()
    ftable = open('index_hash','w')
    with open('page_number_sql1.log','r') as fr:
    #with open('proof_index','r') as fr:
        lines = fr.readlines()
        for l in lines:
            linelist = l.strip().split(" ")
            #hash = hashlib.sha256()
            table[int(linelist[1])]= linestr[int(linelist[1])]              
            #ftable.write(str(linelist[1])+" "+linestr[int(linelist[1])]+"\n")  
            pageindex.append(int(linelist[1]))
    ftable.close()
    fr.close()
    print('Proof Decommitment Prepare..........')
    print('Tree Node: '+str(len(tree)))
    decommitment = []
    decommitment = proof(tree,pageindex)
    num_leafs = len(linestr)
    depth = int(math.log2(num_leafs))
    start = time.time()
    flag = verify(Root, depth, table, decommitment, debug_print=False)
    end = time.time()  
    print("Proof_flag: "+str(flag))
    print ("Proof_Time: "+str(end-start)+"s")
    print('End Verify..........')
if __name__ == '__main__':
    main()
