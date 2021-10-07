// #define _WIN32_WINNT 0x0500
#include <windows.h>]
#include <winnt.h>
#include <Sddl.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <filesystem>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <stdlib.h>
#include <errno.h>

#define MAX 100
// Prototype
BOOL CreateMyDACL(SECURITY_ATTRIBUTES* pSA);
BOOL CreateMyDACL_file(SECURITY_ATTRIBUTES* pSA);
BOOL CreateMyDACL_template(SECURITY_ATTRIBUTES* pSA);
BOOL CreateMyDACL_reset(SECURITY_ATTRIBUTES* pSA);



using namespace std;

//Hash code

string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int wmain(int argc, WCHAR** argv)
{
    vector<string> fname; // Содержат имя файлов 
    

    string line, passw;
    ifstream myfile;
    int pwd = 0;

    const WCHAR reset_template[] = L"C:\\Users\\dungphan16499\\source\\repos\\ModifyACL\\TestACL\\template.tbl";
    LPCWSTR lpFileName_reset = (LPCWSTR)reset_template;

    SECURITY_ATTRIBUTES  sa_folder, sa_file, sa_template, sa_reset, sa_ALL;
    BOOL RetVal, RetVal2, RetVal_template, RetVal_reset, RetVal_ALL;

    sa_reset.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa_reset.bInheritHandle = FALSE;

    RetVal_reset = CreateMyDACL_reset(&sa_reset);

    if (!RetVal_reset)
    {
        // Произошла ошибка; сгенерируйте сообщение и просто выйдите. 
        wprintf(L"Failed CreateMyDACL() for reset, error % d\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"CreateMyDACL() for reset is OK! Returned value is % d\n", RetVal_reset);
    // Мы должны сбросить разрешение шаблона файла на его чтение, потому что после первого запуска этот файл будет заблокирован 
    SetFileSecurity( // Устанавливаем SECURITY_ATTRIBUTE для объекта (папки) 
        lpFileName_reset,
        DACL_SECURITY_INFORMATION,
        sa_reset.lpSecurityDescriptor
    );

    myfile.open("C:\\Users\\dungphan16499\\source\\repos\\ModifyACL\\TestACL\\template.tbl");

    if (myfile.is_open())
    {
        while (getline(myfile, line))
        {
            if (pwd == 0)
                passw = line;               
            else
            {
                fname.push_back(line);
                cout << line << '\n';
            }
            pwd++;
        }
        myfile.close();
    }
    else
        cout << "Unable to open file";


    const WCHAR tmp_lpFileName[] = L"C:\\Users\\dungphan16499\\source\\repos\\ModifyACL\\TestACL"; // Это объект, который нам нужно изменить SECURITY_ATTRIBUTES 
    LPCWSTR lpFileName = (LPCWSTR)tmp_lpFileName;

    const WCHAR tmp_lpFileName_template[] = L"C:\\Users\\dungphan16499\\source\\repos\\ModifyACL\\TestACL\\template.tbl";
    LPCWSTR lpFileName_template = (LPCWSTR)tmp_lpFileName_template;
    LPCWSTR lpFileName2;

    // Размер структуры SECURITY_ATTRIBUTE 
    sa_folder.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa_file.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa_template.nLength = sizeof(SECURITY_ATTRIBUTES);

    // Дескриптор возврата не унаследован 
    sa_folder.bInheritHandle = FALSE;
    sa_file.bInheritHandle = FALSE;
    sa_template.bInheritHandle = FALSE;

    RetVal = CreateMyDACL(&sa_folder);
    RetVal2 = CreateMyDACL_file(&sa_file);
    RetVal_template = CreateMyDACL_template(&sa_template);

    int cnt = 0;
    int tmp = 0;
    
    while (tmp_lpFileName[tmp] != '\0')
        tmp++;
    cnt = tmp + 1;
    for (int k = 0; k < fname.size(); k++)
    {
        WCHAR tmp_lpFileName2[MAX] = L"C:\\Users\\dungphan16499\\source\\repos\\ModifyACL\\TestACL\\";// Это объект, который нам нужно изменить SECURITY_ATTRIBUTES 
        WCHAR* pnt = tmp_lpFileName2;
        pnt = new WCHAR(cnt + fname[k].length());
        pnt = tmp_lpFileName2;
        char* tab2 = new char[fname[k].length() + 1];
        strcpy(tab2, fname[k].c_str());

        for (int j = 0; j < fname[k].length(); j++)
            pnt[cnt + j] = tab2[j];

        lpFileName2 = (LPCWSTR)pnt;
        
        SetFileSecurity( // Устанавливаем SECURITY_ATTRIBUTE для объекта (файлов) 
            lpFileName2,
            DACL_SECURITY_INFORMATION,
            sa_file.lpSecurityDescriptor);
    }

    // Вызов функции CreateMyDACL () для установки DACL.
    // DACL устанавливается в члене SECURITY_ATTRIBUTES lpSecurityDescriptor. 

    if (!RetVal)
    {
        // Произошла ошибка; сгенерируйте сообщение и просто выйдите. 
        wprintf(L"Failed CreateMyDACL() for folder, error % d\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"CreateMyDACL() for folder is OK! Returned value is % d\n", RetVal);

    if (!RetVal2)
    {
        // Произошла ошибка; сгенерируйте сообщение и просто выйдите. 
        wprintf(L"Failed CreateMyDACL() for files, error % d\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"CreateMyDACL() for files is OK! Returned value is % d\n", RetVal2);

    if (!RetVal_template)
    {
        // Произошла ошибка; сгенерируйте сообщение и просто выйдите. 
        wprintf(L"Failed CreateMyDACL() for template, error % d\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"CreateMyDACL() for template is OK! Returned value is % d\n", RetVal_template);


    SetFileSecurity( // Устанавливаем SECURITY_ATTRIBUTE для объекта (папки) 
        lpFileName,
        DACL_SECURITY_INFORMATION,
        sa_folder.lpSecurityDescriptor
    );

    SetFileSecurity( // Устанавливаем SECURITY_ATTRIBUTE для объекта (фыайлы) 
        lpFileName_template,
        DACL_SECURITY_INFORMATION,
        sa_template.lpSecurityDescriptor
    );
 
    // Use the updated SECURITY_ATTRIBUTES to specify security attributes for securable objects.
    // This example uses security attributes during creation of a new directory.
   /*
    if (CreateDirectory(DirName, &sa) == 0)
    {
        // Error encountered; generate message and exit.
        wprintf(L"CreateDirectory() failed lol!Error % d\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"CreateDirectory(), % s directory was successfully created!\n", DirName);
    */

    // Release the memory allocated for the SECURITY_DESCRIPTOR.
    if (LocalFree(sa_folder.lpSecurityDescriptor) != NULL)
    {
        // Error encountered; generate message and exit.
        wprintf(L"LocalFree() for folder failed, error % d.\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"Memory for sa.lpSecurityDescriptor folder was released...\n");

    if (LocalFree(sa_file.lpSecurityDescriptor) != NULL)
    {
        // Error encountered; generate message and exit.
        wprintf(L"LocalFree() for files failed, error % d.\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"Memory for sa.lpSecurityDescriptor files was released...\n");

    if (LocalFree(sa_template.lpSecurityDescriptor) != NULL)
    {
        // Error encountered; generate message and exit.
        wprintf(L"LocalFree() for template failed, error % d.\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"Memory for sa.lpSecurityDescriptor template was released...\n");

    if (LocalFree(sa_reset.lpSecurityDescriptor) != NULL)
    {
        // Error encountered; generate message and exit.
        wprintf(L"LocalFree() for reset failed, error % d.\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"Memory for sa.lpSecurityDescriptor reset was released...\n");

    wprintf(L"Protect mode has been turned ON\n");
    // После запуска эта программа, файлы будут в защищенном режиме, пока мы не введем правильный пароль 
    string pdw = "d158a22b173f598f285fee32278665c15c4efdf3bec340e8f0dcf2877448c49e"; //pad16499
    string buff_pwd;
    cout << "Password: ";
    cin >> buff_pwd;

    while (sha256(buff_pwd) != pdw)
    {
        cout << "Wrong password!! pls try again" << endl;
        cin >> buff_pwd;
    }

    cout << "Password correct !!\n";

    // Выключение режима защиты при правильном пароле 
    sa_ALL.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa_ALL.bInheritHandle = FALSE;

    RetVal_ALL = CreateMyDACL_reset(&sa_ALL);

    if (!RetVal_ALL)
    {
        // Error encountered; generate message and just exit.
        wprintf(L"Fail to turn off protect mode for template, error % d\n", GetLastError());
        exit(1);
    }
    else
        wprintf(L"Protect mode has been turned OFF! Returned value is % d\n", RetVal_ALL);

    SetFileSecurity( //Set SECURITY_ATTRIBUTE for object (Folder)
        lpFileName_reset,
        DACL_SECURITY_INFORMATION,
        sa_ALL.lpSecurityDescriptor
    );

    for (int k = 0; k < fname.size(); k++)
    {
        WCHAR tmp_lpFileName2[MAX] = L"C:\\Users\\dungphan16499\\source\\repos\\ModifyACL\\TestACL\\";
        WCHAR* pnt = tmp_lpFileName2;
        pnt = new WCHAR(cnt + fname[k].length());
        pnt = tmp_lpFileName2;
        char* tab2 = new char[fname[k].length() + 1];
        strcpy(tab2, fname[k].c_str());

        for (int j = 0; j < fname[k].length(); j++)
            pnt[cnt + j] = tab2[j];

        lpFileName2 = (LPCWSTR)pnt;

        SetFileSecurity( //Set SECURITY_ATTRIBUTE for object (Files)
            lpFileName2,
            DACL_SECURITY_INFORMATION,
            sa_ALL.lpSecurityDescriptor);
    }

    SetFileSecurity( //Set SECURITY_ATTRIBUTE for object (Folder)
        lpFileName,
        DACL_SECURITY_INFORMATION,
        sa_ALL.lpSecurityDescriptor
    );

    ofstream myfileW;
    myfileW.open("C:\\Users\\dungphan16499\\source\\repos\\ModifyACL\\TestACL\\template.tbl");
    myfileW << pdw << endl;
    for (int k = 0; k < fname.size(); k++)
        myfileW << fname[k] << endl;
    myfileW.close();

    system("pause");
    return 0;

}

// CreateMyDACL ()
// Создаем дескриптор безопасности, содержащий нужный вам DACL.
// Эта функция использует SDDL для создания запрещающих и разрешающих записей ACE.
//
// Параметр:
// SECURITY_ATTRIBUTES * pSA
// Указатель на структуру SECURITY_ATTRIBUTES. Это звонящий
// ответственность за правильную инициализацию структуры и освобождение структуры
// Член lpSecurityDescriptor, когда вызывающий закончил его использовать.
// Чтобы освободить член структуры lpSecurityDescriptor, вызовите функцию LocalFree.
//
// Возвращаемое значение:
// ЛОЖЬ, если адрес структуры ПУСТО. В противном случае эта функция возвращает значение из
// Функция ConvertStringSecurityDescriptorToSecurityDescriptor (). 
BOOL CreateMyDACL(SECURITY_ATTRIBUTES* pSA)
{
    PULONG nSize = 0;

    const WCHAR* szSD = L"D:"           // Дискреционный ACL 
        L"(D;OICI;GA;;;BG)"           // Запрещаем доступ встроенным гостям 
                                       
        L"(D;OICI;GA;;;AN)"         // Запрещаем доступ к анонимному входу 
                                      

        //L"(D;OICI;GX;;;AU)"
        L"(A;OICI;GR;;;AU)"           // Разрешить чтение для аутентификации 
        //L"(D;OICI;GWSD;;;AU)"                           
                                      
        //L"(D;OICI;GW;;;BU)"
                                      

        L"(A;OICI;GR;;;BA)";        // Разрешить чтение администратору 
        //L"(D;OICI;GWSD;;;BA)";


    if (pSA == NULL)
        return FALSE;
    else
        wprintf(L"SECURITY_ATTRIBUTES was passed...\n");

    // Выполняем некоторые проверки 

    wprintf(L"The ACE strings : % s \n", szSD);
    wprintf(L"The size : % d \n", pSA->nLength);
    wprintf(L"The converted string is at : % p \n", &(pSA->lpSecurityDescriptor));

    // Преобразуем строку в двоичный дескриптор безопасности и вернем 
    return ConvertStringSecurityDescriptorToSecurityDescriptor(
        szSD,                         // Строки ACE 
        SDDL_REVISION_1,              // Стандартный уровень ревизии 
        &(pSA->lpSecurityDescriptor), // Указатель на преобразованный дескриптор безопасности 
        nSize);                // Размер в байтах преобразованного дескриптора безопасности 


}

BOOL CreateMyDACL_file(SECURITY_ATTRIBUTES* pSA)
{
    PULONG nSize = 0;

   

    const WCHAR* szSD2 = L"D:"        // Дискреционный ACL 
        L"(D;OICI;FA;;;BG)"           // Запрещаем доступ встроенным гостям 
                                       
        L"(D;OICI;FA;;;AN)"           // Запрещаем доступ к анонимному входу 
                                      

        //L"(D;OICI;GX;;;AU)"
        //L"(A;OICI;GR;;;AU)" 
        //L"(A;OICI;FX;;;AU)" 
        L"(D;OICI;FW;;;AU)"             // Запрещаем чтение для аутентификации                           
        //L"(D;OICI;GWSD;;;AU)"                          
                                                        
        //L"(A;OICI;FX;;;BA)"
        L"(D;OICI;FW;;;BA)";            // Запрещаем чтение администратору                       
        //L"(A;OICI;FR;;;BA)";
        //L"(A;OICI;GR;;;BA)";


    if (pSA == NULL)
        return FALSE;
    else
        wprintf(L"SECURITY_ATTRIBUTES was passed...\n");

    // Выполняем некоторые проверки 

    wprintf(L"The ACE strings : % s \n", szSD2);
    wprintf(L"The size : % d \n", pSA->nLength);
    wprintf(L"The converted string is at : % p \n", &(pSA->lpSecurityDescriptor));
    return ConvertStringSecurityDescriptorToSecurityDescriptor(
        szSD2,                         // The ACE strings
        SDDL_REVISION_1,              // Standard revision level
        &(pSA->lpSecurityDescriptor), // Pointer to the converted security descriptor
        nSize);                // The size in byte the converted security descriptor
}

BOOL CreateMyDACL_template(SECURITY_ATTRIBUTES* pSA)
{
    PULONG nSize = 0;

    const WCHAR* szSD3 = L"D:"          // Discretionary ACL
        L"(D;OICI;GA;;;BG)"           // Deny access to 
                                      // built-in guests
        L"(D;OICI;GA;;;AN)"          // Deny access to 
                                     // anonymous logon

        //L"(D;OICI;GX;;;AU)"
        L"(D;OICI;FA;;;BA)"             // Разрешить чтение для аутентификации 
       
        //L"(D;OICI;GWSD;;;AU)"                           
                              
        //L"(D;OICI;GW;;;BU)"
                              
        L"(D;OICI;FA;;;AU)";          // Запрещаем чтение администратору 

    //L"(D;OICI;GWSD;;;BA)";


    if (pSA == NULL)
        return FALSE;
    else
        wprintf(L"SECURITY_ATTRIBUTES was passed...\n");

    // Выполняем некоторые проверки 
    wprintf(L"The ACE strings : % s \n", szSD3);
    wprintf(L"The size : % d \n", pSA->nLength);
    wprintf(L"The converted string is at : % p \n", &(pSA->lpSecurityDescriptor));

    // Convert the string to the security descriptor binary and return
    return ConvertStringSecurityDescriptorToSecurityDescriptor(
        szSD3,                         // The ACE strings
        SDDL_REVISION_1,              // Standard revision level
        &(pSA->lpSecurityDescriptor), // Pointer to the converted security descriptor
        nSize);                // The size in byte the converted security descriptor

}
// Эта функция сбросит все права доступа к объектам (Разрешить доступ (запись, чтение, изменение) всем пользователям) 
BOOL CreateMyDACL_reset(SECURITY_ATTRIBUTES* pSA)
{
    PULONG nSize = 0;

    const WCHAR* szSD_reset = L"D:"    // Discretionary ACL
        L"(D;OICI;GA;;;BG)"           // Deny access to 
                                      // built-in guests
        L"(D;OICI;GA;;;AN)"          // sDeny access to 
                                     // anonymous logon

        //L"(D;OICI;GX;;;AU)"
        L"(A;OICI;FA;;;BA)"
        // Allow 
        //L"(D;OICI;GWSD;;;AU)"         
                                       
        //L"(D;OICI;GW;;;BU)"
                                      
        L"(A;OICI;FA;;;AU)";

    //L"(D;OICI;GWSD;;;BA)";


    if (pSA == NULL)
        return FALSE;
    else
        wprintf(L"SECURITY_ATTRIBUTES was passed...\n");

    // Do some verifications

    wprintf(L"The ACE strings : % s \n", szSD_reset);
    wprintf(L"The size : % d \n", pSA->nLength);
    wprintf(L"The converted string is at : % p \n", &(pSA->lpSecurityDescriptor));

    // Convert the string to the security descriptor binary and return
    return ConvertStringSecurityDescriptorToSecurityDescriptor(
        szSD_reset,                         // The ACE strings
        SDDL_REVISION_1,              // Standard revision level
        &(pSA->lpSecurityDescriptor), // Pointer to the converted security descriptor
        nSize);                // The size in byte the converted security descriptor

}


