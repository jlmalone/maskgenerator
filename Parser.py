# This programme is for password guessing.
# It takes a file of initial word seeds.
# It takes a maximum number of capital letters in the initial word.
# It takes a maximum character number of Salting/Filler/Etraneous Numbers,UpperAlphas,LowerAlphas,$pecial Character.
# It takes a dictionary of potential keystroke errors, ie. one might hit 'w' accidentally instead of intended 'q'
# It takes a dictionary of unshifted to shifted characters
# It takes a set of potential $pecial Characters in the extraneous.
# It takes inputs for maximum Upper Characters of Original $eed
# It takes max number of keystroke errors
# It takes a minimum number of Numbers,UpperAlphas,LowerAlphas,$pecial Character for the final output
# It generates every permutation of extraneous character eg

# for a set of extraneous Characters containing 2 Uppers, One Number, and One $pecial:
# UU#$,U#U$,#UU$,UU$#,U$U#,$UU#,$#UU,#$UU,U$#U,U#$U
# for a set of extraneous Characters containing 1 Lower, One Upper, One Number, and One $pecial:
# UL#$,U#L$,#UL$,UL$#,U$L#,$UL#,$#UL,#$UL,U$#L,U#$L,LU#$,L#U$,#LU$,LU$#,L$U#,$LU#,$#LU,#$LU,L$#U,L#$U

# and so on. These extraneous character permutations (ECP) are combined.

# The original seed is expanded into word candidates by generating every combination of string
# containing uppercase letters up to the max allowed in the input (might be one or 2)

# Optional TODO: A reversal set with caps lock down is generated for each value. If a ranking system is implemented,
# these are placed at the lowest rank.

# The expanded seed list is then further expanded with Keystroke error possibilities.
# This operation will roughly expand the set by set by 7 * len(seed).
# It also includes a keystoke deletion and a doubletap

# eg pqssword, [assword, assword, ppassword, PPassword

# Optional TODO: add possibilities for extra insertion where the user had fat fingers eg:
# poassword, passeword, etc


# ECPs are then Tmesis combined (deck shuffled) with the characters from the seed.

# eg. PasswordUL#$, UPasswordL#$, ..., UPasLswo#rd$ ...

# Optional TODO. There may be an optional input added to rank masks based on liklihood. This will help
# in the case of resource constrains to prioritise likely candidates.

# Every seed word is combined with every other seed word including itself up to Three times.
# The maximum Upper for seeds is doubled (trebbled when self referential)
# This forms a new set of Seeds, and all the previous steps are repeated.

# The Placeholders for ECPs are replaced finally with custom charactersets and formatting and saved
# in an .hcmask file

# eg. #$%^&*,Password?u?l?d?1 where #$%^&* -> ?1 is the input special character set.

# The output file is intended to be run with hashcat to find a password solution to a particular hash or cipher





KEYSTROKE_ERROR_MAP = {'`':['1'], '1':['`', '2', 'q'], '2':['1', 'q', 'w', '3'], '4':['3', 'e', 'r', '5'], '3':['2', 'w', 'e', '4'] , '5':['4', 'r', 't', '6'], '6':['5', 't', 'y', '7'], '7':['6', 'y', 'u', '8'], '8':['7', 'u', 'i', '9'], '9':['8', 'i', 'o', '0'], '0':['9', 'o', 'p', '-'], '-':['0', 'p', '[', '='], '=':['-', '[', ']'],
        'q':['1','2','w','a'],'w':['q','2','3','e','s','a'],'e':['3','w','s','d','r','4'],'r':['4','e','d','f','t','5'],'t':['r','5','6','y','g','f'],'y':['t','g','h','u','7','6'],'u':['7','y','h','j','i','8'],'i':['u','j','k','o','9','8'],'j':['h','n','m','k','i','u'],'o':['9','0','p','l','k','i'],'p':['o','l',';','[','-','0'],'h':['g','b','n','j','u','y']}



results = []
final = []
with open('seed.txt') as inputfile:
    i = 0
    for line in inputfile:
        print type(line)
        results.append(line.strip().split(','))

        print line
        print 'hellp world'
        c = results[i]
        print 'c is '+str(type(c))
        i=i+1

for s in results:
    print type(s)
    print str(s)
    print '\n'
    v = s




for r in results:
    base = ''.join(r)
    # print str(base)
    for ind in range(len(base)):
        print base + ' '+str(ind)+' '+base[ind]
        cha =  base[ind]
        mistakes = [cha, '', cha + cha]
        mergedmistakes = []
        if KEYSTROKE_ERROR_MAP.has_key(cha):

            print 'HAS KEY: '+cha
            print KEYSTROKE_ERROR_MAP[cha]

            mergedmistakes = KEYSTROKE_ERROR_MAP[cha]

        mergedmistakes = mergedmistakes + mistakes

        prefix = base[:ind]
        suffix = base[ind + 1:]
        possibilities = []


        for i in range(len(mergedmistakes)):


            possibilities.append((prefix+mergedmistakes[i]+suffix))

        final += possibilities


for f in final:
    print 'f '+f


