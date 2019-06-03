def fastfile():
    while True:
        for i in range(50):
            print(' ')
        print('> Enter Filename')
        print('>> Example: Test.txt')
        file_name = str(input(' @ : '))
        try:
            endfile = open(file_name,'rt').read()
            print('>>> A file with this name already exists!')
            input('> Please, Try Again | ')
        except FileNotFoundError:
            open(file_name,'a')
            print(f'>>> {file_name} Has Been Created!')
            choice = str(input(' # More? | Y - Yes | N - No | : '))
            if choice == 'Y' or choice == 'y':
                pass
            else:
                break
fastfile()
