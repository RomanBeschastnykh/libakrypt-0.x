#include <stdio.h>
#include <libakrypt.h>

typedef struct rand_hash {
/* структура используемой бесключевой функции хеширования */
	struct hash ctx;
/* счетчик обработанных блоков */
	ak_mpzn512 counter;
/* выработанные значения */
	ak_uint8 buffer[64];
/* количество доступных для выдачи октетов */
	size_t len;
} *ak_random_hash;


/*Функция, генерирующая следующее значение хэш-функции, контекст которой передаётся в объекте-параметре*/
int ak_random_hash_next( ak_random rnd ){
    ak_random_hash hrnd = NULL;
    ak_mpzn512 one = ak_mpzn512_one;

    if( rnd == NULL ){ 
        ak_error_message( ak_error_null_pointer, __func__ ,
    "use a null pointer to a random generator" );
        return 0;
    }
    /* вырабатываем новые значения */
    hrnd = ( ak_random_hash )&rnd->data;
    if( hrnd->len != 0 ){ 
        ak_error_message( ak_error_wrong_length, __func__,
    "unexpected use of next function" );
        return 0;
    }
    
    ak_mpzn_add( hrnd->counter, hrnd->counter, one, ak_mpzn512_size );
    /* вычисляем новое хеш-значение */
    ak_hash_ptr( &hrnd->ctx, hrnd->counter, 64, hrnd->buffer, 64 );
    
    struct mac mc = hrnd->ctx.mctx;
    hrnd->len = mc.bsize;

    return ak_error_ok;
}



/*Вычисляем случайные данные*/
int ak_random_hash_randomize_ptr( ak_random rnd,
const ak_pointer ptr, const ssize_t size ) {
    ak_random_hash hrnd = NULL;
    if( rnd == NULL || ptr == NULL || !size){
        return ak_error_message( ak_error_null_pointer, __func__ ,
"use a null pointer to a parameter" );
    }

    hrnd = ( ak_random_hash )&rnd->data;
    hrnd->len = 0;
    memset( hrnd->counter, 0, 64 );
    memset( hrnd->buffer, 0, 64 );


    struct mac mc = hrnd->ctx.mctx;
    if(( size <= 47 ) || ( mc.bsize > 64 )){
        memcpy( hrnd->counter+2, ptr, ak_min( size, 47 ));
    } else {
	ak_uint8 buffer[64]; 
	memset( buffer, 0x11, 64 );
	ak_hash_ptr( &hrnd->ctx, ptr, size, buffer, size );
	memcpy( hrnd->counter+2, buffer, 47 );
    }

    ak_random_hash_next( rnd );
    return ak_error_ok;
}


/*Выработка случайного значения*/
int ak_random_hash_random( ak_random rnd, const ak_pointer ptr, const ssize_t size ) {
    ak_uint8 *inptr = ptr;
    size_t realsize = size;
    ak_random_hash hrnd = NULL;

    if( rnd == NULL ){ 
        return ak_error_message( ak_error_null_pointer, __func__ ,
"use a null pointer to a random generator" );
    }
    
    if( ptr == NULL ){ 
        return ak_error_message( ak_error_null_pointer, __func__ ,
"use a null pointer to data" );
    }
    
    if( !size ){ 
        return ak_error_message( ak_error_zero_length, __func__ ,
"use a data with zero length" );
    }
    hrnd = ( ak_random_hash )&rnd->data;

    while( realsize > 0 ) {
	size_t offset = ak_min( realsize, hrnd->len );
	struct mac mc = hrnd->ctx.mctx;
	memcpy( inptr, hrnd->buffer + (mc.bsize - hrnd->len), offset );
	inptr += offset;
	realsize -= offset;
	if(( hrnd->len -= offset ) <= 0 ){
	    ak_random_hash_next( rnd );
	}    
    }
    return ak_error_ok;
}




/*Освобождает ресурсы, затраченные при создании контекста*/
int ak_random_hash_free( ak_random ptr ) {
    int error = ak_error_ok;
    if( ptr == NULL ) {
	ak_error_message( ak_error_null_pointer, __func__ , "freeing a null pointer to data" );
	return 0;
    }
    
    if(( error = ak_hash_destroy( &(( ak_random_hash )ptr)->ctx )) != ak_error_ok ){
	ak_error_message( error, __func__ , "wrong destroying internal hash function context" );
    }	

    free(ptr);
}




/*Функция, реализующая генератор случайных чисел, на основании ГОСТа Р 1-323565.1-006-2017
@param oid - oid бесключевой функции хэширования
@param generator - структура, используеая в качестве генератора
*/
int *ak_gost_1323565_1_006_2017(ak_oid oid, ak_random generator) {

    int error;
    char* oidname;
    
    struct random rand;
    ak_random_hash hashRnd;

    /*Проверки на соответствие таким параметрам, как тип хэш-функции, проверка на null и т.д.*/
    if(oid == NULL || oid->engine != hash_function || oid->mode != algorithm){
        ak_error_message(ak_error_null_pointer, __func__, "OID is null");
        return 0;
    }

    if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
        ak_libakrypt_destroy();
        return (int *)1;
    } 
    
    /* Начальное состояние генератора*/
    
    generator->oid = NULL;
    generator->next = NULL;
    generator->randomize_ptr = NULL;
    generator->random = NULL;
    generator->free = NULL;
    
    memset( &generator->data, 0, sizeof( generator->data ));
    
    if(( error = ak_hash_create_oid( generator->data.ctx, oid )) != ak_error_ok ) {
	ak_random_destroy( generator );
	ak_error_message( error, __func__ ,
"incorrect creation of internal hash function context" );
	return 0;
    }
    
    hashRnd->len = 0;
    memset( hashRnd->counter, 0, 64 );
    memset( hashRnd->buffer, 0, 64 );
    ak_snprintf( oidname, 30, "hashprng-%s", oid->name );

    /*Определяем параметры ГПСЧ*/

    generator->oid = ak_oid_find_by_name( oidname );
    generator->next = ak_random_hash_next;
    generator->randomize_ptr = ak_random_hash_randomize_ptr;
    generator->random = ak_random_hash_random;
    generator->free = ak_random_hash_free;
    
    error = ak_random_create_lcg( &rand );
    
    if( error != ak_error_ok ) {
        ak_random_destroy( generator );
        ak_error_message( error, __func__ ,
"incorrect creation of internal random generator context" );
        return 0;
    }
    /* один старший и 16 младший октетов останутся нулевыми */
    ak_random_randomize( &rand, hashRnd->counter+2, 47 );
    ak_random_destroy( &rand );
    
    /* вычисляем псевдо-случайные данные */
    ak_random_hash_next( generator );
    
    ak_libakrypt_destroy();
    
    return 0;
}


/*Функция для тестирования описанной выше функции получения ПСЧ*/
bool_t test_ak_gost_1323565_1_006_2017() {
    struct hash streebog;
    struct random generator;
    ak_oid oid = ak_oid_find_by_name("streebog512");
    bool_t exitcode = ak_true;
    ak_uint8 cnt[128], buffer[526], out[32], string[2050];
    printf("\nTest for %s hash function\n", oid->name );

/* хеш для контрольной суммы */
    ak_hash_create_streebog256( &streebog ); 

    memset( cnt, rand()%512, sizeof( cnt )); /* константа для инициализации ГПСЧ*/
    ak_gost_1323565_1_006_2017( oid, &generator ); 
    
    ak_random_randomize( &generator, cnt, sizeof( cnt )); 
    
    /* вырабатываем псевдослучайное значение */
    ak_random_create_random( &generator ); 

    ak_ptr_to_hexstr_alloc( buffer, sizeof( buffer ), ak_false );
    printf("data: %s\n\n", string );

    ak_hash_ptr( &streebog, buffer, sizeof( buffer ), out, sizeof( out )); /* контрольная сумма от выработанных данных */
    
    ak_ptr_to_hexstr_alloc( out, sizeof( out ), ak_false );
    printf("hash: %s\n", string );
    
    ak_random_destroy( &generator );
    ak_hash_destroy( &streebog );

    return exitcode;
}
