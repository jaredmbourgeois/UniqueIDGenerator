//
//  UIDGenerator.mm
//
//  Created by Jared Bourgeois on 5/24/19.
//  Copyright © 2019 Jared Bourgeois. All rights reserved.
//

#import "UIDGenerator.h"

@implementation UIDGenerator

+ (NSString *)uniqueID {
  std::string UID = generateUniqueID();
  return [NSString stringWithCString:UID.c_str() encoding:kCFStringEncodingUTF8];
}

@end