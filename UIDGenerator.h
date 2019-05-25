//
//  UIDGenerator.h
//
//  Created by Jared Bourgeois on 5/24/19.
//  Copyright © 2019 Jared Bourgeois. All rights reserved.
//

#ifndef UIDGenerator_h
#define UIDGenerator_h

#import <Foundation/Foundation.h>
#include "uniqueIDGenerator.hpp"

@interface UIDGenerator : NSObject

+ (NSString *)uniqueID;

@end
#endif /* UIDGenerator_h */