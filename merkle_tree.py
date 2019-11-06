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
            #queue += [(index // 2, hash_node(hash, decommitment[0]))]
            #decommitment = decommitment[1:]
            queue += [(index // 2, hash_node(hash,decommitment.get()))]
            #Q.put((index // 2, hash_node(hash, decommitment.get())))
        # Odd nodes can get merged with their neighbour
        elif len(queue) > 0 and queue[0][0] == index - 1:
                # Take the sibbling node from the stack
                (_, sibbling_hash) = queue.pop(0)
                #queue = queue[1:]
                print("run")
                # Merge the two nodes
                queue += [(index // 2, hash_node(sibbling_hash,hash))]
                #Q.put((index // 2, hash_node(sibbling_hash, hash)))
        # Remaining odd nodes are merged with a decommitment on the left
        else:
            # Merge with a decommitment hash on the left
            #queue += [(index // 2, hash_node(decommitment[0], hash))]
            #decommitment = decommitment[1:]
            queue += [(index // 2, hash_node(decommitment.get(), hash))]
            #Q.put((index // 2, hash_node(decommitment.get(), hash)))
        count = count + 1
        print(count)
def main():
    f = open('Page','r')
    line = f.read().strip()
    linestr = line.split("\n")
    f.close()
    print('MerkleTree Prepare..........')
    tree = make_tree(linestr)
    Root = root(tree)
    print('MerkleTree root: '+Root)
    pageindex1=[]
    pageindex2=[]
    pageindex3=[]
    pageindex4=[]
    table1={}
    table2={}
    table3={}
    table4 = {}
    with open('page_number_sql1.log','r') as fr:
    #with open('proof_index','r') as fr:
        lines = fr.readlines()
        for l in lines:
            linelist = l.strip().split(" ")
            if linelist[0] == "page_index" and int(linelist[1]) <= int(0.25*len(linestr)):
                #hash = hashlib.sha256()
                table1[int(linelist[1])]= linestr[int(linelist[1])]
                pageindex1.append(int(linelist[1]))
            if linelist[0] == "page_index" and int(0.25*len(linestr)) < int(linelist[1]) <= int(0.5*len(linestr)):
                #hash = hashlib.sha256()
                table2[int(linelist[1])]= linestr[int(linelist[1])]
                pageindex2.append(int(linelist[1]))
            if linelist[0] == "page_index" and int(0.5*len(linestr)) < int(linelist[1]) <= int(0.75*len(linestr)):
                #hash = hashlib.sha256()
                table3[int(linelist[1])]= linestr[int(linelist[1])]
                pageindex3.append(int(linelist[1]))
            if linelist[0] == "page_index" and int(0.75*len(linestr)) < int(linelist[1]) <= int(len(linestr)):
                #hash = hashlib.sha256()
                table4[int(linelist[1])-1]= linestr[int(linelist[1])-1]
                pageindex4.append(int(linelist[1]))
    
    fr.close()
    print('Proof Decommitment Prepare..........')
    print('Tree len: '+str(len(tree)))
    print(int(0.25*len(linestr)))
    decommitment1 =decommitment2 =decommitment3 =decommitment4 = []
    decommitment1 = proof(tree,pageindex1)
    decommitment2 = proof(tree,pageindex2)
    decommitment3 = proof(tree,pageindex3)
    decommitment4 = proof(tree,pageindex4)
    num_leafs = len(linestr)
    depth = int(math.log2(num_leafs))
    start1 = time.time()
    flag1 = verify(Root, depth, table1, decommitment1, debug_print=False)
    end1 = time.time()
    start2 = time.time()
    flag2 = verify(Root, depth, table2, decommitment2, debug_print=False)
    end2 = time.time()
    start3 = time.time()
    #flag3 = verify(Root, depth, table3, decommitment3, debug_print=False)
    end3 = time.time()
    start4 = time.time()
    #flag4 = verify(Root, depth, table4, decommitment4, debug_print=False)
    end4 = time.time()
    print("Proof_1_flag: "+str(flag1))
    print("Proof_2_flag: "+str(flag2))
    #print("Proof_3_flag: "+str(flag3))
    #print("Proof_4_flag: "+str(flag4))
    print ("Proof_1_Time: "+str(end1-start1)+"s")
    print ("Proof_2_Time: "+str(end2-start2)+"s")
    #print ("Proof_3_Time: "+str(end3-start3)+"s")
    #print ("Proof_4_Time: "+str(end4-start4)+"s")
    print('End Verify..........')
if __name__ == '__main__':
    main()
