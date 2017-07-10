/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_random.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_random.h>
 #include <ak_context_manager.h>

 #include <time.h>
 #include <fcntl.h>
 #ifdef LIBAKRYPT_HAVE_UNISTD_H
  #include <unistd.h>
 #endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct random в значения по-умолчанию.

    @param rnd указатель на структуру struct random
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create( ak_random rnd )
{
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  rnd->data = NULL;
  rnd->next = NULL;
  rnd->randomize_ptr = NULL;
  rnd->random = NULL;
  rnd->free = free;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает указатель на структуру struct random, устанавливает поля этой структуры
    в значения по-умолчанию и возвращает указатель на созданную структуру.
    @return Если указатель успешно создан, то он и возвращается. В случае возникновения ошибки
    возвращается NULL.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_random ak_random_new( void )
{
  ak_random rnd = ( ak_random ) malloc( sizeof( struct random ));
  if( rnd != NULL ) ak_random_create( rnd );
   else ak_error_message( ak_error_out_of_memory, __func__ , "incorrect memory allocation" );
  return rnd;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на структуру struct random
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_destroy( ak_random rnd )
{
  if( rnd == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ ,"use a null pointer to a random generator" );
  return ak_error_null_pointer;
  }
  if( rnd->data != NULL ) rnd->free( rnd->data );
  rnd->next = NULL;
  rnd->randomize_ptr = NULL;
  rnd->random = NULL;
  rnd->free = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает все внутренние поля, уничтожает генератор псевдо-случайных чисел
    (структуру struct random) и присваивает указателю значение NULL.

    @param указатель на структуру struct random.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_random_delete( ak_pointer rnd )
{
  if( rnd != NULL ) {
   ak_random_destroy(( ak_random ) rnd );
   free( rnd );
  } else ak_error_message( ak_error_null_pointer, __func__ ,
                                            "use a null pointer to a random generator" );
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
  static ak_uint32 shift_value = 0; // Внутренняя статическая переменная (счетчик вызовов)

/* ----------------------------------------------------------------------------------------------- */
/*! Функция использует для генерации случайного значения текущее время и прочие параметры.
    Несмотря на случайность вырабатываемого значения, функция не должна использоваться для
    генерации значений, для которых требуется криптографическая случайность. Это связано с
    достаточно прогнозируемым изменением значений функции при многократных повторных вызовах.

    Основная задача данной функции - инициализаци программного генератора
    каким-либо знаением, в случае, когда пользователь не инициализирует программный генератор
    самостоятельно.

   \return Функция возвращает случайное число размером 8 байт (64 бита).                                                     */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_random_value( void )
{
  ak_uint64 vtme = time( NULL );
  ak_uint64 clk = clock();
#ifndef _WIN32
  ak_uint64 pval = getpid();
  ak_uint64 uval = getuid();
#else
  ak_uint64 pval = _getpid();
  ak_uint64 uval = 67;
#endif
  ak_uint64 value = ( shift_value += 11 )*125643267795740073LL + pval;
            value = ( value * 506098983240188723LL ) + 71331*uval + vtme;
  return value ^ clk;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_lcg                                       */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения внутренних состояний линейного конгруэнтного генератора              */
 struct random_lcg {
  /*! \brief текущее значение внутреннего состояния генератора */
  ak_uint64 val;
};
 typedef struct random_lcg *ak_random_lcg;

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_next( ak_random rnd )
{
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  (( ak_random_lcg ) ( rnd->data ))->val *= 125643267795740073LL;
  (( ak_random_lcg ) ( rnd->data ))->val += 506098983240188723LL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_randomize_ptr( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  size_t idx = 0;
  ak_uint8 *value = ptr;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to initial vector" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "use initial vector with zero length" );
    return ak_error_null_pointer;
  }
  /* сначала начальное значение, потом цикл по всем элементам массива */
  (( ak_random_lcg ) ( rnd->data ))->val = value[idx];
  do {
        rnd->next( rnd );
        (( ak_random_lcg ) ( rnd->data ))->val += value[idx];
  } while( ++idx < size );
 return rnd->next( rnd );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_random( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  size_t i = 0;
  ak_uint8 *value = ptr;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to data" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "use a data with zero length" );
    return ak_error_zero_length;
  }

  for( i = 0; i < size; i++ ) {
    value[i] = (ak_uint8) ((( ak_random_lcg ) ( rnd->data ))->val >> 16 );
    rnd->next( rnd );
  }
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Данный генератор вырабатывает последовательность внутренних состояний, удовлетворяющую
    линейному сравнению \f$ x_{n+1} \equiv a\cdot x_n + c \pmod{2^{64}}, \f$
    в котором константы a и c удовлетворяют равенствам
    \f$ a = 125643267795740073 \f$ и \f$ b = 506098983240188723. \f$

    Далее, последовательность внутренних состояний преобразуется в последовательность
    байт по следующему правилу
    \f$ \gamma_n = \displaystyle\frac{x_n - \hat x_n}{2^{24}} \pmod{256}, \f$
    где \f$\hat x_n \equiv x_n \pmod{2^{24}}. \f$

    @param generator Контекст создаваемого генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_lcg( ak_random generator )
{
  int error = ak_error_ok;
  ak_uint64 qword = ak_random_value(); /* вырабатываем случайное число */

  if(( error = ak_random_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( generator->data = malloc( sizeof( struct random_lcg ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
              "incorrect memory allocation for an internal variables of random generator" );

  generator->next = ak_random_lcg_next;
  generator->randomize_ptr = ak_random_lcg_randomize_ptr;
  generator->random = ak_random_lcg_random;
 /* функция generator->free уже установлена при вызове ak_random_create */

 /* для корректной работы присваиваем какое-то случайное начальное значение */
  ak_random_lcg_randomize_ptr( generator, &qword, sizeof( ak_uint64 ));
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_file                                      */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения внутренних состояний генератора-файла                                */
 struct random_file {
  /*! \brief файловый дескриптор */
  int fd;
};
 typedef struct random_file *ak_random_file;

/* ----------------------------------------------------------------------------------------------- */
 static void ak_random_file_free( ak_pointer ptr )
{
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "freeing a null pointer to data" );
    return;
  }
  if( close( (( ak_random_file ) ptr )->fd ) == -1 )
    ak_error_message( ak_error_close_file, __func__ , "wrong closing a file with random data" );
  free(ptr);
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_file_random( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  ak_uint8 *value = ptr;
  size_t result = 0, count = size;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to data" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "use a data with zero length" );
    return ak_error_zero_length;
  }

  /* считываем несколько байт */
  slabel:
  result = read( (( ak_random_file ) ( rnd->data ))->fd, value,
  #ifdef _MSC_VER
    (unsigned int)
  #endif
    count );

  /* если конец файла, то переходим в начало */
  if( result == 0 ) {
    lseek( (( ak_random_file ) ( rnd->data ))->fd, 0, SEEK_SET );
    goto slabel;
  }
  /* если мы считали меньше, чем надо */
  if( result < count ) {
    value += result;
    count -= result;
    goto slabel;
  }
  /* если ошибка чтения, то возбуждаем ошибку */
  if( result == -1 ) {
    ak_error_message( ak_error_read_data, __func__ , "wrong reading data from file" );
    return ak_error_read_data;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Данный генератор связывается с заданным файлом и возвращает содержащиеся в нем значения
    в качестве случайных чисел. Если данные в файле заканчиваются, то считывание начинается
    с начала файла.

    Основное назначение данного генератора - считывание данных из файловых устройств,
    таких как /dev/randon или /dev/urandom.

    @param generator Контекст создаваемого генератора.
    @param filename Имя файла.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_file( ak_random generator, const char *filename )
{
  int error = ak_error_ok;
  if(( error = ak_random_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( generator->data = malloc( sizeof( struct random_file ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
           "incorrect memory allocation for an internal variables of random generator" );

 /* теперь мы открываем заданный пользователем файл */
  if( ((( ak_random_file ) ( generator->data ))->fd = open( filename, O_RDONLY | O_BINARY )) == -1 ) {
    ak_error_message_fmt( ak_error_open_file, __func__ ,
                                  "wrong opening a file \"%s\" with random data", filename );
    //generator = ak_random_delete( generator );
    ak_random_destroy( generator );
    return ak_error_open_file;
  }

  generator->next = NULL;
  generator->randomize_ptr = NULL;
  generator->random = ak_random_file_random;
  generator->free = ak_random_file_free; /* эта функция должна закрыть открытый ранее файл */

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                         реализация класса winrtl                                */
/* ----------------------------------------------------------------------------------------------- */
#ifdef _WIN32
 #include <windows.h>
 #include <wincrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения контекста криптопровайдера. */
 struct random_winrtl {
  /*! \brief контекст криптопровайдера */
  HCRYPTPROV handle;
};
 typedef struct random_winrtl *ak_random_winrtl;

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_winrtl_random( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  if( !CryptGenRandom( (( ak_random_winrtl )rnd->data)->handle, size, ptr ))
    return ak_error_message( ak_error_undefined_value, __func__,
                                                    "wrong generation of pseudo random sequence" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static void ak_random_winrtl_free( ak_pointer ptr )
{
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "freeing a null pointer to data" );
    return;
  }
  if( !CryptReleaseContext( (( ak_random_winrtl )ptr )->handle, 0 )) {
    ak_error_message_fmt( ak_error_close_file,
            __func__ , "wrong closing a system crypto provider with error: %x", GetLastError( ));
  }
  free( ptr );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_winrtl( ak_random generator )
{
  HCRYPTPROV handle = 0;

  int error = ak_error_ok;
  if(( error = ak_random_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( generator->data = malloc( sizeof( struct random_winrtl ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
           "incorrect memory allocation for an internal variables of random generator" );

  /* теперь мы открываем криптопровайдер для доступа к генерации случайных значений */
  if( !CryptAcquireContext( &handle, NULL, NULL,
                                         PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT )) {
     ak_error_message_fmt( ak_error_ok, __func__,
                      "wrong opening a system crypto provider with error: %x", GetLastError( ));
     ak_random_destroy( generator );
     return ak_error_open_file;
  }
  (( ak_random_winrtl )generator->data)->handle = handle;

  generator->next = NULL;
  generator->randomize_ptr = NULL;
  generator->random = ak_random_winrtl_random;
  generator->free = ak_random_winrtl_free; /* эта функция должна закрыть открытый ранее криптопровайдер */

 return error;
}

#endif

/* ----------------------------------------------------------------------------------------------- */
/*                               реализация интерфейсных функций                                   */
/* ----------------------------------------------------------------------------------------------- */
 static ak_handle ak_random_new_handle( ak_random generator )
{
  ak_context_manager manager = NULL;
  ak_handle handle = ak_error_wrong_handle;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "using a non initialized context manager" );
    generator = ak_random_delete( generator );
    return ak_error_wrong_handle;
  }

 /* создаем элемент структуры управления контекстами */
  if(( handle = ak_context_manager_add_node(
           manager, generator, random_generator, "", ak_random_delete )) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation of context manager node" );
    generator = ak_random_delete( generator );
    return ak_error_wrong_handle;
  }

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_random_new_lcg( void  )
{
  int error = ak_error_ok;
  ak_random generator = NULL;

 /* создаем генератор */
  if(( generator = malloc( sizeof( struct random ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                                  "wrong creation of random generator context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ak_random_create_lcg( generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of random generator" );
    free( generator );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_random_new_handle( generator );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_random_new_file( const char *filename  )
{
 int error = ak_error_ok;
 ak_random generator = NULL;

 /* создаем генератор */
  if(( generator = malloc( sizeof( struct random ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                                  "wrong creation of random generator context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ak_random_create_file( generator, filename )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization a random generator" );
    free( generator );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_random_new_handle( generator );
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef _WIN32
 ak_handle ak_random_new_winrtl( void  )
{
  int error = ak_error_ok;
  ak_random generator = NULL;

 /* создаем генератор */
  if(( generator = malloc( sizeof( struct random ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                                  "wrong creation of random generator context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ak_random_create_winrtl( generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of random generator" );
    free( generator );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_random_new_handle( generator );
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @param ptr указатель на область памяти, в которую помещаются значения
    @param size размер памяти в байтах
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_ptr( ak_handle handle, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;
  ak_random generator = NULL;

  if(( generator = ak_libakrypt_get_context( handle, random_generator )) == NULL )
    return ak_error_message( error = ak_error_get_value(), __func__ , "wrong handle" );

  if( generator->random != NULL ) {
    if(( error = generator->random( generator, ptr, size )) != ak_error_ok )
      ak_error_message( error, __func__, "wrong generation of random data" );
    return error;
  }
 return ak_error_message( ak_error_undefined_function, __func__ ,
                                                 "use a null pointer to a function " );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @return В случае успеха возвращается псевдо-случайное число.
    В случае возникновения ошибки возвращается ноль. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_random_uint64( ak_handle handle )
{
  ak_uint64 qword = 0;
  ak_random generator = NULL;

  if(( generator = ak_libakrypt_get_context( handle, random_generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );
    return qword;
  }

  if( generator->random != NULL ) {
    if( generator->random( generator, &qword, sizeof( ak_uint64 )) != ak_error_ok )
      ak_error_message( ak_error_get_value(), __func__, "wrong generation of random data" );
    return qword;
  } ak_error_message( ak_error_undefined_function, __func__ ,
                                                    "using a null pointer to a function " );
 return qword;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @return В случае успеха возвращается псевдо-случайное число.
    В случае возникновения ошибки возвращается ноль. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 ak_random_uint8( ak_handle handle )
{
  ak_uint8 byte = 0;
  ak_random generator = NULL;

  if(( generator = ak_libakrypt_get_context( handle, random_generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );
    return byte;
  }

  if( generator->random != NULL ) {
    if( generator->random( generator, &byte, sizeof( ak_uint8 )) != ak_error_ok )
      ak_error_message( ak_error_get_value(), __func__, "wrong generation of random data" );
    return byte;
  } ak_error_message( ak_error_undefined_function, __func__ ,
                                                    "using a null pointer to a function " );
 return byte;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @param size размер создаваемого буффера в байтах
    @return В случае успеха возвращается указатель на созданный буффер. В случае возникновения
    ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_random_buffer( ak_handle handle, const size_t size )
{
 ak_buffer buffer = NULL;
 ak_random generator = NULL;

 /* получаем контекст */
  if(( generator = ak_libakrypt_get_context( handle, random_generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );
    return NULL;
  }

 /* проверяем, что функция генерации определена */
  if( generator->random == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ , "use a null pointer to a function " );
    return NULL;
  }

 /* создаем буффер */
  if(( buffer = ak_buffer_new_size( size )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong buffer creation" );
    return NULL;
  }

 /* вырабатываем псевдо-случайные значения */
  if( generator->random( generator, buffer->data, buffer->size ) != ak_error_ok )
    ak_error_message( ak_error_get_value(), __func__, "wrong generation of random data" );

 return buffer;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle дескриптор генератора псевдо-случайных данных
    @param ptr указатель на область памяти, в которую помещаются значения
    @param size размер памяти в байтах
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_randomize( ak_handle handle, const ak_pointer ptr, const size_t size )
{
 int error = ak_error_ok;
 ak_random generator = NULL;

  if(( generator = ak_libakrypt_get_context( handle, random_generator )) == NULL )
    return ak_error_message( error = ak_error_get_value(), __func__ , "wrong handle" );

  if( generator->randomize_ptr != NULL ) {
       if(( error = generator->randomize_ptr( generator, ptr, size )) != ak_error_ok )
         ak_error_message( error, __func__, "wrong randomization of random generator" );
       return error;
  }
 return ak_error_message( ak_error_undefined_function, __func__ ,
                                                    "use a null pointer to a function " );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-random.c                                                                      */
/*! \example example-randomize.c                                                                   */
/*! \example example-random-system.c                                                               */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_random.c  */
/* ----------------------------------------------------------------------------------------------- */
